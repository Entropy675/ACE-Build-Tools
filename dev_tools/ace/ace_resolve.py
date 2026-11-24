"""ace resolve -- find and fix what this machine lacks before ETCS can do something.

    ace resolve identity [--password-stdin]
                        the loader's key: libsecret, a secrets provider, the
                        user's session bus, the keyring's lock, the store

Also run before every build (identity_preflight, from ace make): in full the
first time per user and machine, then as one line of signing state.

THE KEY IS THE USER'S, NEVER ROOT'S. A loader keeps its key in the keystore of
whoever runs it (core/Keystore.h), under $HOME/.local/share/etcs. Under sudo,
root does only what needs root (packages, lingering, ownership) and everything
else runs as $SUDO_USER: a key minted as root is a second identity, held in a
keyring no user build reaches.

The keyring password is asked for, piped to gnome-keyring-daemon, and dropped.
Nothing here stores it, so a locked keyring after a reboot is unlocked by
running this again.
"""
from pathlib import Path
import ctypes
import getpass
import grp
import os
import platform
import pwd
import shutil
import subprocess
import sys
import time

from .ace_common import CYAN, YELLOW, GREEN, RED, RESET, DIM
from .ace_sign import _HEX64

# manager -> (libsecret, secrets provider, per-user session bus)
_PACKAGES = {
    "apt-get": ("libsecret-1-0", "gnome-keyring", "dbus-user-session"),
    "dnf":     ("libsecret",     "gnome-keyring", "dbus-broker"),
    "pacman":  ("libsecret",     "gnome-keyring", "dbus"),
    "zypper":  ("libsecret-1-0", "gnome-keyring", "dbus-1"),
}

_PROFILE_BEGIN = "# >>> ace resolve identity >>>"
_PROFILE_END   = "# <<< ace resolve identity <<<"
_PROFILE_BODY  = ('[ -z "$DBUS_SESSION_BUS_ADDRESS" ] && [ -S "/run/user/$(id -u)/bus" ] && \\\n'
                  '    export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u)/bus"')

# What libsecret says (under LANG=C) of a keyring that an unlock would fix. Every
# other failure is one the steps before the probe already named.
_LOCKED = ("timeout was reached",           # waiting on a prompt nobody can see
           "collection/login",              # no login keyring yet: the first unlock makes it
           "locked")

_PROBE_TIMEOUT = 10     # seconds; D-Bus's own is 25, spent waiting on a prompt nobody can see


class _Target:
    """The user whose key signs, and the bus that reaches their keystore.

    THE BUS IS THE ONE SIGNING USES. Signing runs bin/etcs in ace's own
    environment, so when ace runs as this user, the bus the build was started
    on (a desktop login, dbus-run-session) is the one asked here too;
    /run/user/<uid>/bus is only the guess for a user ace is not (sudo)."""

    def __init__(self, entry):
        self.name, self.uid, self.gid, self.home = entry.pw_name, entry.pw_uid, entry.pw_gid, entry.pw_dir
        self.groups = os.getgrouplist(self.name, self.gid)
        own = self.uid == os.geteuid()
        self.inherited = (os.environ.get("DBUS_SESSION_BUS_ADDRESS") or None) if own else None
        self.runtime = (os.environ.get("XDG_RUNTIME_DIR") if own else None) or f"/run/user/{self.uid}"

    @property
    def bus(self):
        return Path(f"/run/user/{self.uid}/bus")

    @property
    def address(self):
        return self.inherited or f"unix:path={self.bus}"


class ResolveMixin:

    def resolve(self, args):
        if not args or args[0] != "identity" or any(a != "--password-stdin" for a in args[1:]):
            print("Usage: ace resolve identity [--password-stdin]")
            return 1
        if platform.system() != "Linux":
            print(f"{DIM}[=] nothing to resolve here: Windows keeps the key in the Credential Manager, "
                  f"and a browser holds none{RESET}")
            return 0
        return self._resolve_identity(password_stdin="--password-stdin" in args)

    # ------------------------------------------------------------------

    def _resolve_identity(self, password_stdin=False):
        root = os.geteuid() == 0
        t = self._resolve_target()
        via = " (as root, via sudo)" if root and t.uid != 0 else ""
        print(f"{CYAN}[*] identity for {t.name} (uid {t.uid}){via}{RESET}")
        if root and t.uid == 0:
            print(f"{YELLOW}[!] root with no $SUDO_USER: this resolves ROOT's identity, a different loader "
                  f"from any user's. Run it as `sudo ace resolve identity` from your own account.{RESET}")

        later = []                                   # what only root could have fixed
        self._resolve_libsecret(root, later)
        self._resolve_bus(t, root, later)
        self._resolve_provider(t, root, later)
        self._resolve_profile(t)
        self._resolve_ownership(t, root, later)

        if not self._signer():
            for step in later:
                print(f"{YELLOW}[!] needs root: {step}{RESET}")
            print(f"{DIM}[=] no native bin/etcs yet: the key is checked once the loader is built{RESET}")
            return 2

        state, detail = self._probe_key(t)
        if state == "locked":
            print(f"{YELLOW}[!] the keyring is locked, or there is none yet -- {detail}{RESET}")
            if self._unlock_keyring(t, password_stdin):
                state, detail = self._probe_key(t)

        for step in later:
            print(f"{YELLOW}[!] needs root: {step}{RESET}")
        if later:
            print(f"{DIM}    sudo ace resolve identity{RESET}")
        if state != "ok":
            print(f"{RED}[-] no key: {detail}{RESET}")
            return 1
        print(f"{GREEN}[+] loader key {detail}{RESET}")
        p = self._as_user(t, [str(self._signer()), "--identity"], timeout=_PROBE_TIMEOUT)
        ident = next((l.strip() for l in p.stdout.splitlines() if _HEX64.match(l.strip())), None)
        if ident:
            print(f"{DIM}    identity {ident}{RESET}")
        self._resolve_stray_root_store(t)
        return 0

    # ------------------------------------------------------------------
    # Before every build (ace make)
    # ------------------------------------------------------------------

    _PREFLIGHT_TIMEOUT = 3   # seconds; an unlocked keystore answers in milliseconds

    def _identity_marker(self):
        return self._get_registry_dir() / ".identity_checked"

    def identity_preflight(self):
        """THE SIGNING STATE, BEFORE THE BUILD THAT WILL NEED IT. Signing runs
        after the build (ace sign), so a keystore that can't answer used to be
        found minutes in, at the end. Never stops a build: unsigned modules are
        reported by the sign step as before.

        The first build per user and machine runs the whole resolve (the same
        confirms, so -y answers them); after that, one line, from a probe short
        enough to sit in front of every build. A locked keyring -- every reboot
        on a headless machine -- is offered its unlock at a terminal."""
        if platform.system() != "Linux" or getattr(self, "_identity_preflighted", False):
            return
        # Once per ace run: `ace witness` and `ace wasm make all` call make() more than once.
        self._identity_preflighted = True
        if self.untrusted_setting():
            print(f"{DIM}[=] signing: off -- untrusted loaders (`ace untrusted off` to sign){RESET}")
            return
        t = self._resolve_target()
        stamp = f"{t.name} {platform.node()}"
        marker = self._identity_marker()
        try:
            first = marker.read_text().strip() != stamp
        except OSError:
            first = True
        if first:
            print(f"{CYAN}[*] First build for {t.name} on this machine -- checking the signing identity.{RESET}")
            rc = self._resolve_identity()
            if rc == 0:
                marker.write_text(stamp + "\n")
            elif rc == 1:
                print(f"{DIM}    the build goes on; modules stay unsigned until `ace resolve identity` passes{RESET}")
            return
        if not self._signer():
            print(f"{DIM}[=] signing: no native bin/etcs yet -- the key is checked once it is built{RESET}")
            return
        state, detail = self._probe_key(t, timeout=self._PREFLIGHT_TIMEOUT)
        if state == "locked" and sys.stdin.isatty():
            print(f"{YELLOW}[!] signing: the keyring is locked -- {detail}{RESET}")
            if self._confirm(f"{YELLOW}[?] Unlock it now?{RESET}", False) and self._unlock_keyring(t, False):
                state, detail = self._probe_key(t, timeout=self._PREFLIGHT_TIMEOUT)
        if state == "ok":
            print(f"{GREEN}[+] signing: {t.name}'s loader key {detail[:16]}...{RESET}")
        else:
            print(f"{YELLOW}[!] signing: {detail}{RESET}")
            print(f"{DIM}    modules built now stay unsigned -- `ace resolve identity`{RESET}")

    def offer_keyring_restart(self):
        """A signature timed out on the keystore: offer, at a terminal, to
        restart the keyring daemon and unlock it (_unlock_keyring: --replace,
        then the password). True when the key answers afterwards. Elsewhere it
        only says what to run."""
        print(f"{YELLOW}[!] the keyring did not answer -- its daemon may be stuck, or its password "
              f"prompt was closed or is hidden behind another window{RESET}")
        if platform.system() != "Linux" or not sys.stdin.isatty():
            print(f"{DIM}    `ace resolve identity` at a terminal restarts and unlocks it{RESET}")
            return False
        if not self._confirm(f"{YELLOW}[?] Restart the keyring daemon and unlock it with your password?{RESET}",
                             False):
            return False
        return self._unlock_keyring(self._resolve_target(), False)

    def _resolve_target(self):
        name = os.environ.get("SUDO_USER") if os.geteuid() == 0 else None
        try:
            return _Target(pwd.getpwnam(name) if name else pwd.getpwuid(os.geteuid()))
        except KeyError:
            return _Target(pwd.getpwuid(os.geteuid()))

    def _as_user(self, t, argv, input=None, timeout=None):
        """argv as the target user, with the environment a login of theirs would
        give it: their home, their bus. LANG=C, so the errors read as _LOCKED
        expects."""
        env = {"HOME": t.home, "USER": t.name, "LOGNAME": t.name, "LANG": "C",
               "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
               "XDG_RUNTIME_DIR": t.runtime,
               "DBUS_SESSION_BUS_ADDRESS": t.address}
        if t.uid == os.geteuid():                    # not sudo: what signing sees, so their own overrides hold
            for k in ("HOME", "ETCS_STORE", "XDG_DATA_HOME"):
                if os.environ.get(k):
                    env[k] = os.environ[k]
        drop = {} if t.uid == os.geteuid() else {"user": t.uid, "group": t.gid, "extra_groups": t.groups}
        return subprocess.run(argv, input=input, capture_output=True, text=True, env=env,
                              stdin=None if input is not None else subprocess.DEVNULL,
                              cwd=str(self.ace_root), timeout=timeout, **drop)

    # ------------------------------------------------------------------
    # Root's half: packages, lingering, ownership
    # ------------------------------------------------------------------

    def _install(self, which, why, root, later):
        cmd, mgr = self._package_manager()
        pkg = _PACKAGES.get(mgr, (None, None, None))[which] if mgr else None
        if not pkg:
            later.append(f"{why} -- no known package for this distro; install it by hand")
            return False
        if not root:
            later.append(f"{why} ({pkg})")
            return False
        if not self._confirm(f"{YELLOW}[?] {why}: install {pkg}?{RESET}", False):
            return False
        return subprocess.run([c for c in cmd if c != "sudo"] + [pkg]).returncode == 0

    def _resolve_libsecret(self, root, later):
        try:
            ctypes.CDLL("libsecret-1.so.0")          # the name core/Keystore.h dlopens
            print(f"{GREEN}[+] libsecret{RESET}")
        except OSError:
            if self._install(0, "libsecret-1.so.0 is missing", root, later):
                print(f"{GREEN}[+] libsecret installed{RESET}")

    def _resolve_bus(self, t, root, later):
        if t.inherited:
            print(f"{GREEN}[+] session bus {t.inherited.split(',')[0]} (this build's){RESET}")
            return
        if t.bus.is_socket():
            print(f"{GREEN}[+] session bus {t.bus}{RESET}")
            return
        if not any(Path(d, u).exists() for d in ("/usr/lib/systemd/user", "/lib/systemd/user")
                   for u in ("dbus.socket", "dbus-broker.service")):
            if not self._install(2, "no per-user session bus is installed", root, later):
                return
        lingering = Path(f"/var/lib/systemd/linger/{t.name}").exists()
        if not lingering:
            if not root:
                later.append(f"no session bus without a login: loginctl enable-linger {t.name}")
                return
            if not self._confirm(f"{YELLOW}[?] {t.name} has no session bus without a login. Enable lingering, "
                                 f"so SSH, tmux and cron builds all reach one bus and keyring?{RESET}", False):
                return
            subprocess.run(["loginctl", "enable-linger", t.name])
        elif root:
            subprocess.run(["systemctl", "start", f"user@{t.uid}.service"])
        for _ in range(50):
            if t.bus.is_socket():
                print(f"{GREEN}[+] session bus {t.bus}{RESET}")
                return
            time.sleep(0.1)
        print(f"{RED}[-] still no {t.bus}. Without systemd user sessions, build inside one instead:{RESET}\n"
              f"{DIM}    dbus-run-session -- sh -c 'printf %s \"$PASS\" | gnome-keyring-daemon --unlock "
              f"--components=secrets; ace -y make all'{RESET}")

    def _resolve_provider(self, t, root, later):
        if (t.inherited or t.bus.is_socket()) and "org.freedesktop.secrets" in self._bus_names(t):
            print(f"{GREEN}[+] secrets provider on the bus{RESET}")
            return
        if shutil.which("gnome-keyring-daemon"):
            print(f"{GREEN}[+] gnome-keyring{RESET}")
            return
        if self._install(1, "no secrets provider (org.freedesktop.secrets)", root, later):
            print(f"{GREEN}[+] gnome-keyring installed{RESET}")

    def _bus_names(self, t):
        """Names owned or activatable on the user's bus; empty if it cannot be asked."""
        names = set()
        for method in ("ListNames", "ListActivatableNames"):
            try:
                p = self._as_user(t, ["dbus-send", "--session", "--print-reply", "--dest=org.freedesktop.DBus",
                                      "/org/freedesktop/DBus", f"org.freedesktop.DBus.{method}"], timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                return names
            names |= {l.split('"')[1] for l in p.stdout.splitlines() if l.strip().startswith('string "')}
        return names

    def _resolve_ownership(self, t, root, later):
        """Files a `sudo ace make` left root-owned where the user's builds write."""
        store = Path(t.home, ".local/share/etcs")
        dirs = [store] + ([self._bin_dir()] if self.ace_root.stat().st_uid == t.uid else [])
        wrong = [p for d in dirs if d.exists()
                 for p in [d, *d.rglob("*")] if p.lstat().st_uid != t.uid]
        if not wrong:
            return
        if not root:
            later.append(f"{len(wrong)} files under {store} or bin/ are not {t.name}'s")
            return
        if self._confirm(f"{YELLOW}[?] {len(wrong)} files under {store} or bin/ are not {t.name}'s "
                         f"(a build run as root?). Give them back?{RESET}", False):
            for p in wrong:
                os.lchown(p, t.uid, t.gid)
            print(f"{GREEN}[+] {len(wrong)} files returned to {t.name}{RESET}")

    def _resolve_stray_root_store(self, t):
        if t.uid != 0 and os.geteuid() == 0 and Path("/root/.local/share/etcs").exists():
            print(f"{YELLOW}[!] /root/.local/share/etcs exists: a second identity, minted by a loader run as "
                  f"root. Its key is in root's keyring; left alone.{RESET}")

    # ------------------------------------------------------------------
    # The user's half: the shell, the probe, the lock
    # ------------------------------------------------------------------

    def _resolve_profile(self, t):
        """Point a login shell at the user's bus. The block is fenced and written
        once, so running this again changes nothing."""
        profile = Path(t.home, ".profile")
        text = profile.read_text() if profile.exists() else ""
        if _PROFILE_BEGIN in text:
            print(f"{GREEN}[+] ~/.profile exports the bus{RESET}")
            return
        if not self._confirm(f"{YELLOW}[?] Add DBUS_SESSION_BUS_ADDRESS to {profile}, so shells that did "
                             f"not inherit it (SSH, tmux) find the bus?{RESET}", False):
            return
        block = f"\n{_PROFILE_BEGIN}\n{_PROFILE_BODY}\n{_PROFILE_END}\n"
        with open(profile, "a") as f:
            f.write(block)
        if os.geteuid() != t.uid:
            os.chown(profile, t.uid, t.gid)
        print(f"{GREEN}[+] ~/.profile exports the bus (new shells){RESET}")

    def _probe_key(self, t, timeout=_PROBE_TIMEOUT):
        """(state, detail): 'ok' and the key, or 'locked' / 'fail' and why. The
        real thing: bin/etcs --loader-key as the user, which mints the key on
        first use."""
        signer = self._signer()
        if not signer:
            return "fail", "there is no native bin/etcs -- `ace make loader etcs`, then run this again"
        try:
            p = self._as_user(t, [str(signer), "--loader-key"], timeout=timeout)
        except subprocess.TimeoutExpired:
            return "locked", f"no answer in {timeout} s: the keyring is waiting on an unlock prompt"
        except OSError as e:
            return "fail", str(e)
        key = next((l.strip() for l in p.stdout.splitlines() if _HEX64.match(l.strip())), None)
        if p.returncode == 0 and key:
            return "ok", key
        err = (p.stderr or "").strip()
        last = err.splitlines()[-1] if err else f"bin/etcs --loader-key exited {p.returncode}"
        locked = any(pat in err.lower() for pat in _LOCKED)
        return ("locked" if locked else "fail"), last.split(" -- ")[0]

    def _unlock_keyring(self, t, password_stdin):
        """Unlock the login keyring for this boot; the first unlock creates it.

        Tried as typed, then with a trailing newline: gnome-keyring keeps the
        newline, so a keyring made by `echo "$PASS" | gnome-keyring-daemon
        --unlock` has it in its password, and one made by a login does not."""
        if not shutil.which("gnome-keyring-daemon"):
            print(f"{DIM}    the provider is not gnome-keyring: unlock it the way it asks{RESET}")
            return False
        if password_stdin:
            pw = sys.stdin.readline().rstrip("\n")
        elif sys.stdin.isatty():
            pw = getpass.getpass(f"    keyring password for {t.name} (a new login keyring takes it): ")
        else:
            print(f"{DIM}    not a terminal: pass --password-stdin, or run this from one{RESET}")
            return False
        if not pw:
            return False
        for attempt in (pw, pw + "\n"):
            try:
                self._as_user(t, ["gnome-keyring-daemon", "--replace", "--unlock", "--daemonize",
                                  "--components=secrets"], input=attempt, timeout=15)
            except (OSError, subprocess.TimeoutExpired) as e:
                print(f"{RED}[-] gnome-keyring-daemon: {e}{RESET}")
                return False
            if self._probe_key(t)[0] == "ok":
                print(f"{GREEN}[+] keyring unlocked until the next reboot{RESET}")
                return True
        print(f"{RED}[-] the keyring stayed locked: wrong password?{RESET}")
        return False
