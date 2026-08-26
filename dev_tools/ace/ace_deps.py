"""ace deps subsystem.

Part of the `ace` dev tool, split by causal boundary: this file owns the
deps surface and nothing else. Mixed into AceManager in ace_install.py --
all methods are `self`-bound and may call across subsystems through the one
assembled object, but each subsystem's *definition* lives in exactly one file.
"""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import re

from .ace_common import (CYAN, YELLOW, GREEN, RED, RESET, DIM)


class DepsMixin:

    def _deps_dir(self):
        return self.ace_root / "deps"

    def _deps_marker(self):
        """First-run marker. Lives beside the global registry, NOT in the
        tree -- it records something about the MACHINE, and needs to survive
        a tree being deleted and re-extracted."""
        return self._get_registry_dir() / ".deps_checked"

    def _detect_distro(self):
        """Return an ordered list of distro ids to try, most specific first.

        /etc/os-release ID first, then each entry of ID_LIKE. On Raspberry Pi
        OS that yields ['raspbian', 'debian']; on Ubuntu ['ubuntu', 'debian'].
        Both fall through to the same manifest without needing their own copy.
        """
        candidates = []
        osr = Path("/etc/os-release")
        if osr.exists():
            try:
                fields = {}
                for line in osr.read_text().splitlines():
                    if "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    fields[k.strip()] = v.strip().strip('"').strip("'")
                if fields.get("ID"):
                    candidates.append(fields["ID"])
                for like in fields.get("ID_LIKE", "").split():
                    if like not in candidates:
                        candidates.append(like)
            except Exception as e:
                print(f"  [!] Could not parse /etc/os-release: {e}")
        return candidates

    def _deps_manifest_path(self):
        """Resolve the most specific manifest available for this machine.
        Returns (path, distro_id) or (None, None)."""
        for distro in self._detect_distro():
            path = self._deps_dir() / f"linux-{distro}.txt"
            if path.exists():
                return path, distro
        return None, None

    def _parse_deps(self, path):
        """Parse a manifest into a list of (package, probe) pairs."""
        entries = []
        for raw in path.read_text().splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            package = parts[0]
            probe = parts[1] if len(parts) > 1 else "none"
            entries.append((package, probe))
        return entries

    def _run_probe(self, probe):
        """Evaluate one probe.

        Returns True (present), False (missing), or None (unprobeable --
        reported as UNKNOWN rather than silently assumed good).
        """
        if probe == "none":
            return None

        kind, _, arg = probe.partition(":")

        if kind == "binary":
            return shutil.which(arg) is not None

        if kind == "pkgconfig":
            if not shutil.which("pkg-config"):
                return None  # cannot probe without the prober
            try:
                r = subprocess.run(["pkg-config", "--exists", arg], capture_output=True)
                return r.returncode == 0
            except Exception:
                return None

        if kind == "header":
            search = ["/usr/include", "/usr/local/include"]
            # Multiarch: /usr/include/aarch64-linux-gnu, x86_64-linux-gnu, ...
            inc = Path("/usr/include")
            if inc.is_dir():
                for sub in inc.iterdir():
                    if sub.is_dir() and sub.name.endswith("-linux-gnu"):
                        search.append(str(sub))
            return any((Path(d) / arg).exists() for d in search)

        print(f"  [!] Unknown probe kind '{kind}' -- treating as unprobeable.")
        return None

    def _package_manager(self):
        """Return (install_command_prefix, manager_name), or (None, None)."""
        for mgr, cmd in [
            ("apt-get", ["sudo", "apt-get", "install", "-y"]),
            ("dnf",     ["sudo", "dnf", "install", "-y"]),
            ("pacman",  ["sudo", "pacman", "-S", "--needed"]),
            ("zypper",  ["sudo", "zypper", "install", "-y"]),
        ]:
            if shutil.which(mgr):
                return cmd, mgr
        return None, None

    def deps_check(self, quiet=False):
        """Probe every manifest entry.

        Returns the list of missing package names, or None if no manifest
        exists for this system (which is a different condition from 'nothing
        missing' and must not be confused with it).
        """
        path, distro = self._deps_manifest_path()
        if not path:
            print(f"  [!] No dependency manifest for this system.")
            print(f"      Tried: {', '.join(self._detect_distro()) or '(none detected)'}")
            print(f"      Expected e.g. {self._deps_dir() / 'linux-debian.txt'}")
            print(f"      Write one -- the format is documented at the top of any existing manifest.")
            return None

        entries = self._parse_deps(path)

        # Module manifests declare their own system packages, in the same
        # (package, probe) vocabulary this file already speaks. Folding them
        # in here is what makes a manifest a COMPLETE statement of what a
        # module needs: `ace deps check` covers the tree's modules without the
        # machine manifest having to name every module's dependencies too.
        try:
            for pkg, probe in self.manifest_system_packages():
                if not any(pkg == p for p, _ in entries):
                    entries.append((pkg, probe))
        except AttributeError:
            pass  # ManifestMixin not assembled (partial tool build)

        if not quiet:
            print(f"\n--- ETCS Dependencies ({distro}, {platform.machine()}) ---")
            print(f"  {DIM}manifest: {path}{RESET}\n")

        missing = []
        unknown = []
        for package, probe in entries:
            result = self._run_probe(probe)
            if result is True:
                status = f"{GREEN}OK     {RESET}"
            elif result is False:
                status = f"{RED}MISSING{RESET}"
                missing.append(package)
            else:
                status = f"{YELLOW}UNKNOWN{RESET}"
                unknown.append(package)
            if not quiet:
                print(f"  {status} {package:<20} {DIM}{probe}{RESET}")

        if not quiet:
            print()
            if missing:
                print(f"  {RED}{len(missing)} missing.{RESET} Run: ace deps install")
            elif unknown:
                print(f"  {GREEN}All probeable dependencies present{RESET}"
                      f" {DIM}({len(unknown)} unprobeable){RESET}")
            else:
                print(f"  {GREEN}All dependencies present.{RESET}")

        return missing

    def deps_install(self, silent=False):
        """Install whatever deps_check reports as missing."""
        missing = self.deps_check()
        if missing is None:
            return
        if not missing:
            self._mark_deps_checked()
            return

        install_cmd, mgr = self._package_manager()
        if not install_cmd:
            print(f"\n  [!] No supported package manager found.")
            print(f"      Install manually: {' '.join(missing)}")
            return

        full = install_cmd + missing
        print(f"\n  Will run ({mgr}):")
        print(f"    {' '.join(full)}\n")

        if not self._confirm("  Proceed?", silent):
            print("  [*] Skipped.")
            return

        try:
            subprocess.run(full, check=True)
        except subprocess.CalledProcessError as e:
            print(f"  [-] Install failed: {e}")
            return
        except FileNotFoundError:
            print(f"  [-] Could not execute {mgr}.")
            return

        print(f"\n  [*] Re-probing...")
        still_missing = self.deps_check(quiet=True)
        if still_missing:
            print(f"  {YELLOW}Still missing after install: {' '.join(still_missing)}{RESET}")
            print(f"  {DIM}A package that installs but does not probe usually means the")
            print(f"  manifest names the wrong package for this distro -- fix the")
            print(f"  manifest, not the probe.{RESET}")
        else:
            print(f"  {GREEN}All dependencies present.{RESET}")
            self._mark_deps_checked()

    def deps_arch(self):
        """Report machine properties that affect whether this tree can build
        and RUN here. Nothing reported here is installable -- that is the
        entire point of it being a separate command."""
        print(f"\n--- ETCS Machine Probe ---")
        print(f"  arch          {platform.machine()}")
        print(f"  kernel        {platform.release()}")

        # Compiler target -- catches a cross-compiler or multilib surprise
        # before the linker does.
        try:
            r = subprocess.run(["g++", "-dumpmachine"], capture_output=True, text=True)
            if r.returncode == 0:
                print(f"  g++ target    {r.stdout.strip()}")
        except FileNotFoundError:
            print(f"  g++ target    {RED}g++ not found{RESET}")

        # Linkers. loaders/Makefile passes -fuse-ld=gold; gold is deprecated
        # upstream and some distros have already dropped it, in which case
        # the fix is a Makefile change to lld -- NOT a package install, which
        # is exactly why this lives here and not in the manifest.
        found = [n for n in ("ld.gold", "ld.lld", "ld.bfd", "ld.mold") if shutil.which(n)]
        print(f"  linkers       {', '.join(found) if found else RED + 'none found' + RESET}")
        if "ld.gold" not in found:
            print(f"    {YELLOW}-fuse-ld=gold will fail. Switch loaders/Makefile to -fuse-ld=lld.{RESET}")

        # io_uring: the syscalls can exist while policy forbids them. This
        # builds clean and fails at RUNTIME, which is the nastier failure.
        sysctl = Path("/proc/sys/kernel/io_uring_disabled")
        if sysctl.exists():
            try:
                val = sysctl.read_text().strip()
                label = {"0": "enabled for all",
                         "1": "restricted to io_uring_group",
                         "2": "DISABLED"}.get(val, "unknown")
                colour = RED if val == "2" else (YELLOW if val == "1" else GREEN)
                print(f"  io_uring      {colour}{val} ({label}){RESET}")
                if val == "2":
                    print(f"    {RED}ThreadPool will build fine and fail at runtime.{RESET}")
            except Exception as e:
                print(f"  io_uring      {YELLOW}unreadable: {e}{RESET}")
        else:
            print(f"  io_uring      {DIM}no sysctl (kernel default policy){RESET}")

        try:
            print(f"  page size     {os.sysconf('SC_PAGE_SIZE')}")
        except (ValueError, AttributeError):
            pass
        print(f"  cpus          {os.cpu_count()}")
        print()

    def _mark_deps_checked(self):
        """Record that this machine passed. Keyed on distro+arch so moving the
        same $HOME to a different machine re-triggers the check rather than
        inheriting a stale pass."""
        _, distro = self._deps_manifest_path()
        self._deps_marker().write_text(f"{distro or 'unknown'} {platform.machine()}\n")

    def _deps_first_run(self, silent=False):
        """Cheap gate called before a build. Runs the full check exactly once
        per (distro, arch), then never again unless the marker is deleted or
        the machine changes underneath it."""
        if platform.system() == "Windows":
            return  # no manifest format for Windows yet

        marker = self._deps_marker()
        _, distro = self._deps_manifest_path()
        current = f"{distro or 'unknown'} {platform.machine()}"

        if marker.exists():
            try:
                if marker.read_text().strip() == current:
                    return  # already verified on this exact machine
            except Exception:
                pass

        print(f"[*] First build on this machine ({current}) -- checking dependencies.")
        missing = self.deps_check()
        if missing is None:
            return
        if not missing:
            self._mark_deps_checked()
            return

        if self._confirm("\n  Install them now?", silent):
            self.deps_install(silent=silent)
        else:
            print(f"  {DIM}Skipped. Run 'ace deps install' when ready; "
                  f"the build will likely fail until then.{RESET}\n")

    def deps(self, args):
        """Dispatch for `ace deps ...`."""
        sub = args[0] if args else "check"
        if   sub == "check":   self.deps_check()
        elif sub == "install": self.deps_install()
        elif sub == "arch":    self.deps_arch()
        else:
            print(f"[-] Unknown deps command: '{sub}'")
            print(f"    Usage: ace deps {{ check | install | arch }}")
