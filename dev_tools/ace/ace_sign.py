"""ace sign -- every module binary carries the chain that lets a loader load it.

    ace sign            sign every current module artifact in bin/ and bin/wasm/,
                        and the native loader binaries in bin/
    ace release [store] sign bin/etcs as a release, with the release machine's
                        loader: the binary the site serves for download
    ace publish [dir]   what the site serves at /dist: the current modules, the
                        last release, and the marketplace's signed list of them
    ace pin <root.cert | hex | clear>
                        the root every loader built here is compiled with
    ace bundle <dir> [module...]
                        bin/etcs and the modules a machine with nothing else on
                        it needs to run the ceremony (or anything else)

Runs by itself after every module and loader build; the command is for when
the loader's key or registration changed under artifacts that did not.

ACE HOLDS NO KEY. The loader does, in the OS keystore (core/Trust.h,
core/Keystore.h): ace asks `bin/etcs --sign` for the chain -- the loader's
leaf and its registration up to the root -- and only places its bytes, so the
private half never leaves the loader. A machine with no keystore signs
nothing, and says how to get one. Where the bytes go, and which bytes the
signature covers, is core/Signature.h:

    ELF   section .etcs.sig, by objcopy
    wasm  custom section etcs.sig, appended
    PE    trailer: chain | len u32le | "ETCSSIG1"

ONLY CURRENT ARTIFACTS ARE SIGNED: an artifact whose build record matches the
tree's sources and generated hashes now. Signing is a witness that these bytes
are this tree's build under this epoch; an artifact older than the tree is not
that, whichever loader is asked.

THE EPOCH IS ace's, NOT THE SIGNER's. `ace make modules` runs before the loader
is rebuilt, so the bin/etcs that signs may be a build behind. The epoch comes
from the generated hash headers, by the rule loader_epoch() applies to the
manifest they fill; after a native loader build the two are compared.
"""
from pathlib import Path
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile

from .ace_common import CYAN, YELLOW, GREEN, RED, RESET, DIM

_EPOCH_PREFIXES = ("CORE:", "ONTOLOGY:", "LIB:", "HEADER:")
_MANIFEST_LINE = re.compile(r'getManifest\(\)\["([^"]+)"\]\s*=\s*"([^"]*)"')
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_LINEAGE = re.compile(r"^etcs-lineage [12] ")

_ELF_SECTION = ".etcs.sig"
_WASM_SECTION = b"etcs.sig"
_PE_TRAILER = b"ETCSSIG1"


def _uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _read_uleb(b, i):
    v, shift = 0, 0
    while True:
        if i >= len(b) or shift > 28:
            raise ValueError("bad LEB128")
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        if not c & 0x80:
            return v, i
        shift += 7


def wasm_with_chain(data, chain):
    """`data` with every etcs.sig custom section removed and `chain` appended
    as the one that remains. Other sections keep their bytes and order, which
    is what the digest covers."""
    if data[:4] != b"\0asm":
        raise ValueError("not wasm")
    out = bytearray(data[:8])
    i = 8
    while i < len(data):
        start = i
        sid = data[i]
        size, j = _read_uleb(data, i + 1)
        end = j + size
        if end > len(data):
            raise ValueError("wasm section past the end")
        ours = False
        if sid == 0:
            nl, k = _read_uleb(data, j)
            ours = data[k:k + nl] == _WASM_SECTION
        if not ours:
            out += data[start:end]
        i = end
    body = _uleb(len(_WASM_SECTION)) + _WASM_SECTION + chain
    out += b"\0" + _uleb(len(body)) + body
    return bytes(out)


def pe_with_chain(data, chain):
    if data[:2] != b"MZ":
        raise ValueError("not PE")
    if len(data) >= 12 and data[-8:] == _PE_TRAILER:
        n = int.from_bytes(data[-12:-8], "little")
        if n > len(data) - 12:
            raise ValueError("PE signature trailer longer than the file")
        data = data[:len(data) - 12 - n]
    return data + chain + len(chain).to_bytes(4, "little") + _PE_TRAILER


class SignMixin:

    def epoch_id(self):
        """BLAKE2b-256 of "ETCSEPO1" then key NUL value NUL over the contract
        and lib entries of the generated hash headers, sorted -- loader_epoch()
        over the manifest those same headers fill."""
        entries = []
        for name in ("core_hashes.h", "ontology_hashes.h", "libs_hashes.h"):
            path = self.ace_root / name
            if not path.is_file():
                continue
            for k, v in _MANIFEST_LINE.findall(path.read_text(errors="replace")):
                if k.startswith(_EPOCH_PREFIXES):
                    entries.append((k, v))
        h = hashlib.blake2b(digest_size=32)
        h.update(b"ETCSEPO1")
        for k, v in sorted(set(entries)):
            h.update(k.encode() + b"\0" + v.encode() + b"\0")
        return h.hexdigest()

    def _signer(self):
        exe = self._bin_dir() / ("etcs.exe" if platform.system() == "Windows" else "etcs")
        return exe if exe.is_file() and os.access(exe, os.X_OK) else None

    def _ask_loader(self, signer, *args, want=_HEX64, env=None):
        """(returncode, the answer line or None, stderr). The loader logs to
        stdout as it starts and stops; the answer is the line that matches
        `want` -- by default, one that is nothing but a key or an epoch."""
        # stdin closed and a timeout: a bin/etcs from before signing reads
        # "--sign" as a script it cannot open and falls into its REPL.
        try:
            p = subprocess.run([str(signer), *args], capture_output=True, text=True,
                               stdin=subprocess.DEVNULL, timeout=120,
                               env=None if env is None else {**os.environ, **env})
        except subprocess.TimeoutExpired:
            return 2, None, "bin/etcs did not answer -- it predates signing; `ace make loader etcs`"
        except OSError as e:
            return 2, None, str(e)
        if "cannot open script file '--" in (p.stderr or ""):
            return 2, None, "bin/etcs predates signing; `ace make loader etcs` and it signs these"
        line = next((l.strip() for l in p.stdout.splitlines() if want.match(l.strip())), None)
        return p.returncode, line, (p.stderr or "").strip()

    def builder_key(self):
        """(key, why). The native loader's public key, made on first use -- the
        loader whose local half a web loader built here extends
        (ETCS_BUILDER_KEY)."""
        return self._loader_answer("--loader-key")

    def _off_root(self, signer, env=None):
        """Why `signer` cannot sign a release for this tree, or None. A release
        is ACE's half: a signer built for another root, or none, signs only its
        local half, which no download takes. Modules and a developer's own
        loaders need no root -- the local half runs on its own loader."""
        pin = self.root_pin()
        if not pin:
            return None
        rc, root, err = self._ask_loader(signer, "--root", env=env)
        if rc == 0 and root == pin:
            return None
        if rc != 0 or not root:
            return err.splitlines()[-1] if err else "bin/etcs gave no root"
        return (f"it signs under root {root[:12]}, and this tree pins {pin[:12]}; "
                f"register its key under the pinned root first (`bin/etcs --registration`)")

    def _loader_answer(self, verb):
        signer = self._signer()
        if not signer:
            return None, "there is no native bin/etcs"
        rc, key, err = self._ask_loader(signer, verb)
        if rc == 0 and key:
            return key, None
        return None, (err.splitlines()[-1] if err else f"bin/etcs {verb} exited {rc}")

    def check_loader_epoch(self):
        """A native loader just built must hold the epoch ace signs under, or
        every module ace signs from here on is refused by it."""
        signer = self._signer()
        if not signer:
            return True
        rc, theirs, err = self._ask_loader(signer, "--epoch")
        ours = self.epoch_id()
        if rc != 0 or not theirs:
            print(f"{YELLOW}[!] bin/etcs gave no epoch: {err or 'no answer'}{RESET}")
            return False
        if theirs != ours:
            print(f"{RED}[-] bin/etcs is in epoch {theirs or '?'} but ace signs for {ours} -- "
                  f"modules signed now will be refused. ace_sign.py and core/Trust.h "
                  f"no longer agree on what an epoch is.{RESET}")
            return False
        return True

    def _module_current(self, mod, web):
        """The build-skip check's record, asked of one artifact: the last build
        of this module was for this platform, from these sources, against these
        generated hashes. Other flags are not provenance -- a DEBUG build of
        this tree is still this tree's build. The record is one per module, so
        a native build makes the .wasm beside it not current, and the other
        way round: it keeps whatever signature it has, it gets no new one."""
        path = self._fingerprint_path(mod)
        if not path.is_file():
            return False
        try:
            with open(path, "r", encoding="utf-8") as fh:
                old = json.load(fh)
        except (OSError, ValueError):
            return False
        if ("EMSCRIPTEN=1" in old.get("flags", "").split()) != web:
            return False
        new = self._module_fingerprint(mod, [])
        return all(old.get(k) == new[k] for k in ("global", "local", "manifest"))

    def _place_chain(self, art, chain_path):
        data = art.read_bytes()
        chain = Path(chain_path).read_bytes()
        tmp = art.with_name(art.name + ".signing")
        if data[:4] == b"\x7fELF":
            objcopy = shutil.which("objcopy")
            if not objcopy:
                return "objcopy not found"
            p = subprocess.run([objcopy, "--remove-section", _ELF_SECTION,
                                "--add-section", f"{_ELF_SECTION}={chain_path}",
                                "--set-section-flags", f"{_ELF_SECTION}=noload,readonly",
                                str(art), str(tmp)], capture_output=True, text=True)
            if p.returncode != 0:
                tmp.unlink(missing_ok=True)
                return (p.stderr or "objcopy failed").strip()
        elif data[:4] == b"\0asm":
            tmp.write_bytes(wasm_with_chain(data, chain))
        elif data[:2] == b"MZ":
            tmp.write_bytes(pe_with_chain(data, chain))
        else:
            return "not ELF, wasm or PE"
        shutil.copymode(art, tmp)
        os.replace(tmp, art)
        return None

    def _sign_one(self, signer, mod, art, epoch, verb="--sign", env=None):
        """'signed', 'unchanged', or why not. With --succeed, also the lineage
        edge the signer recorded (or None): (result, edge)."""
        with tempfile.TemporaryDirectory(prefix="ace-sign-") as d:
            out = Path(d) / "chain"
            rc, edge, err = self._ask_loader(signer, verb, mod, str(art), epoch, str(out), want=_LINEAGE, env=env)
            if rc == 3:
                result = "unchanged"
            elif rc != 0 or not out.is_file():
                result = err.splitlines()[-1] if err else f"bin/etcs {verb} exited {rc}"
            else:
                result = self._place_chain(art, out) or "signed"
            return (result, edge) if verb == "--succeed" else result

    # ------------------------------------------------------------------
    # The loader's own binary, and the lineage
    # ------------------------------------------------------------------
    #
    # A loader is the one binary nothing else checks, so it attests itself
    # (core/Trust.h), and the next etcs is signed by the one going out: ace
    # keeps a copy of bin/etcs before a loader build replaces it, and that copy
    # signs its successor. Where there is no outgoing loader, or it cannot sign
    # (it predates this, or holds no key), the new one signs itself -- which is
    # where a lineage starts, and what a canonical root will allow only once.
    # Every other loader binary (the Run_* testers) is signed by the new etcs.

    def keep_outgoing(self):
        """A copy of bin/etcs under its own name, or None. Its name matters:
        a binary attests itself as what it is called."""
        exe = self._signer()
        if not exe:
            return None
        d = Path(tempfile.mkdtemp(prefix="ace-outgoing-"))
        shutil.copy2(exe, d / exe.name)
        return d / exe.name

    def sign_loaders(self, outgoing, names):
        """Sign the loader binaries just built into bin/. Returns how many
        were left unsigned."""
        try:
            new = self._signer()
            if not new:
                return 0
            epoch = self.epoch_id()
            suffix = ".exe" if platform.system() == "Windows" else ""
            left = 0
            if "etcs" in names:
                result, edge, by = "no signer", None, None
                for signer, who in ((outgoing, "the outgoing loader"), (new, "itself")):
                    if not signer:
                        continue
                    by = who
                    result, edge = self._sign_one(signer, "etcs", new, epoch, verb="--succeed")
                    if result in ("signed", "unchanged"):
                        break
                # A signature the new loader does not take -- the outgoing one signed
                # under a half the new one has no root for -- is no attestation.
                # The new loader may then sign itself where its own rule allows.
                if result == "signed" and by == "the outgoing loader":
                    rc, _, _ = self._ask_loader(new, "--attest", want=re.compile(r"^attested\s"))
                    if rc != 0:
                        again, _ = self._sign_one(new, "etcs", new, epoch, verb="--succeed")
                        if again == "signed":
                            by = "the outgoing loader, then itself: the first signature did not attest it"
                if result in ("signed", "unchanged"):
                    rc, line, _ = self._ask_loader(new, "--attest", want=re.compile(r"^attested\s"))
                    if rc != 0 and line:
                        print(f"{YELLOW}[!] bin/etcs does not attest -- {line.split(':', 1)[-1].strip()}{RESET}")
                if result == "signed":
                    print(f"{GREEN}[+] bin/etcs signed by {by}{RESET}")
                    if edge:
                        f = dict(kv.split("=", 1) for kv in edge.split()[3:] if "=" in kv)
                        print(f"{DIM}    lineage: {f.get('parent', '?')[:12]} -> {f.get('child', '?')[:12]}"
                              f"  epoch {f.get('from', '?')[:12]} -> {f.get('to', '?')[:12]}"
                              f"  on {f.get('host', '?')}{RESET}")
                elif result != "unchanged":
                    left += 1
                    print(f"{RED}[-] bin/etcs is not signed -- {result}{RESET}")
            for name in names:
                art = self._bin_dir() / (name + suffix)
                if name == "etcs" or not art.is_file():
                    continue
                result = self._sign_one(new, name, art, epoch)
                if result not in ("signed", "unchanged"):
                    left += 1
                    print(f"{RED}[-] bin/{name} is not signed -- {result}{RESET}")
            return left
        finally:
            if outgoing:
                shutil.rmtree(outgoing.parent, ignore_errors=True)

    def sign_modules(self, only=None, quiet=False, web=None):
        """Sign every current module artifact -- native, web (web=True), or
        both (None). Returns the number left unsigned or failed; 0 is the good
        answer."""
        mods = sorted(set(self._all_manifests()) | set(self._defaulted_modules()))
        if only is not None:
            mods = [m for m in mods if m in set(only)]
        arts = []
        for mod in mods:
            for art, is_web in ((self._bin_dir() / f"{mod}.{self._lib_ext()}", False),
                                (self._bin_dir() / "wasm" / f"{mod}.wasm", True)):
                if art.is_file() and web in (None, is_web):
                    arts.append((mod, art, is_web))
        if not arts:
            return 0
        signer = self._signer()
        if not signer:
            print(f"{YELLOW}[!] {len(arts)} module artifact(s) left unsigned: there is no "
                  f"bin/etcs to sign with yet. `ace make loader <name>` signs them; "
                  f"a loader refuses them until then.{RESET}")
            return len(arts)
        epoch = self.epoch_id()
        signed, kept, stale, failed = [], [], [], []
        for mod, art, is_web in arts:
            if not self._module_current(mod, is_web):
                stale.append(art.name)
                continue
            r = self._sign_one(signer, mod, art, epoch)
            if "predates signing" in r:
                print(f"{YELLOW}[!] {len(arts)} module artifact(s) left unsigned: {r}.{RESET}")
                return len(arts)
            if r == "signed":
                signed.append(art.name)
            elif r == "unchanged":
                kept.append(art.name)
            else:
                failed.append((art.name, r))
        if signed and not quiet:
            print(f"{GREEN}[+] signed for epoch {epoch[:12]} ({len(signed)}):{RESET}")
            self._print_name_grid(signed, per_row=4, indent="    ", color=CYAN)
        if kept and not quiet:
            print(f"{DIM}[=] already signed for this epoch: {len(kept)}{RESET}")
        if stale:
            print(f"{YELLOW}[!] not signed, older than the tree ({len(stale)}) -- "
                  f"rebuild to sign:{RESET}")
            self._print_name_grid(stale, per_row=4, indent="    ", color=DIM)
        # One line per reason: a missing keystore fails every module alike.
        reasons = {}
        for name, why in failed:
            reasons.setdefault(why.split(": ", 2)[-1] if why.startswith("etcs: ") else why, []).append(name)
        for why, names in reasons.items():
            print(f"{RED}[-] not signed ({len(names)}) -- {why}{RESET}")
            self._print_name_grid(names, per_row=4, indent="    ", color=RED)
        return len(stale) + len(failed)

    def sign(self, args):
        if args:
            print("Usage: ace sign")
            return 1
        if not self._ensure_generated():
            return 1
        if self._run_root_make("generate_hashes"):
            os.environ["ACE_HASHES_READY"] = "1"
        self.check_loader_epoch()
        # The loader binaries too: after a new registration bin/etcs no longer
        # attests under the old chain, and it is the one that re-signs itself.
        suffix = ".exe" if platform.system() == "Windows" else ""
        loaders = ["etcs"] + sorted(p.name[:len(p.name) - len(suffix)] if suffix else p.name
                                    for p in self._bin_dir().glob("Run_*Loader" + suffix))
        left = self.sign_loaders(None, loaders)
        return 1 if (self.sign_modules() or left) else 0

    # ------------------------------------------------------------------
    # A release: the loader the site serves for download
    # ------------------------------------------------------------------
    #
    # bin/etcs signed by the release machine's loader -- a store whose key the
    # active key certified as a release key. A loader binary a release key
    # signed attests on any machine that holds the same root, with an empty
    # store; one signed by a loader's own key attests only on that loader.
    #
    # The signer is the last release this store made, kept beside it as
    # <store>/etcs: it attests anywhere, so it may sign the next. The first
    # release is bin/etcs signing itself -- the release lineage's genesis.

    def _release_store(self, args):
        if args:
            return Path(args[0]).expanduser().resolve()
        env = os.environ.get("ETCS_RELEASE_STORE")
        return Path(env).expanduser().resolve() if env else Path.home() / ".local" / "share" / "etcs-release"

    def release(self, args):
        if len(args) > 1:
            print("Usage: ace release [<store>]")
            return 1
        if not self.root_pin():
            print(f"{RED}[-] a release is signed under ACE's root, and none is pinned (ACE_ROOT_KEY).{RESET}")
            return 1
        new = self._signer()
        if not new:
            print(f"{RED}[-] there is no bin/etcs to release. `ace make loader etcs` first.{RESET}")
            return 1
        if not self._ensure_generated():
            return 1
        if self._run_root_make("generate_hashes"):
            os.environ["ACE_HASHES_READY"] = "1"
        if not self.check_loader_epoch():
            return 1
        store = self._release_store(args)
        env = {"ETCS_STORE": str(store)}
        p = subprocess.run([str(new), "--attest"], capture_output=True, text=True, stdin=subprocess.DEVNULL,
                           timeout=120, env={**os.environ, **env})
        if not re.search(r"^key\s+[0-9a-f]{64} \(release, proven\)$", p.stdout, re.M):
            print(f"{RED}[-] {store} is not a release machine's loader: its key is not registered as a "
                  f"release key, or the keystore does not hold it.{RESET}")
            print(f"{DIM}    ETCS_STORE={store} bin/etcs --loader-key, have the active key certify it as "
                  f"release, then --registration.{RESET}")
            return 1
        kept = store / new.name
        epoch = self.epoch_id()
        result, edge, by = "no signer", None, None
        for signer, who in ((kept if kept.is_file() else None, "the last release"), (new, "itself")):
            if not signer:
                continue
            result, edge, by = self._off_root(signer, env=env), None, who
            if result:
                continue
            result, edge = self._sign_one(signer, "etcs", new, epoch, verb="--succeed", env=env)
            if result in ("signed", "unchanged"):
                break
        if result not in ("signed", "unchanged"):
            print(f"{RED}[-] bin/etcs is not released -- {result}{RESET}")
            return 1
        shutil.copy2(new, kept)
        if result == "unchanged":
            print(f"{DIM}[=] bin/etcs is already this release{RESET}")
        else:
            print(f"{GREEN}[+] bin/etcs released, signed by {by}{RESET}")
        if edge:
            f = dict(kv.split("=", 1) for kv in edge.split()[3:] if "=" in kv)
            print(f"{DIM}    lineage: {f.get('parent', '?')[:12]} -> {f.get('child', '?')[:12]}"
                  f"  epoch {f.get('from', '?')[:12]} -> {f.get('to', '?')[:12]}"
                  f"  on {f.get('host', '?')}{RESET}")
        return 0


    # ------------------------------------------------------------------
    # What the site serves at /dist
    # ------------------------------------------------------------------
    #
    # The current module binaries, the last release (<release store>/etcs), and
    # bin/etcs --manifest's list of them: the marketplace's signature over each
    # one's digest and epochs, and over the epoch the site is in. A loader reads
    # the list (CryptProvider::Upstream) and fetches what it is behind on. What
    # a download would not take -- a module only this loader's own key signed --
    # is left off by the loader, and said.

    def publish(self, args):
        if len(args) > 1:
            print("Usage: ace publish [<dir>]")
            return 1
        if not self.root_pin():
            print(f"{RED}[-] a site publishes under ACE's root, and none is pinned (ACE_ROOT_KEY).{RESET}")
            return 1
        signer = self._signer()
        if not signer:
            print(f"{RED}[-] there is no bin/etcs to sign the list. `ace make loader etcs` first.{RESET}")
            return 1
        if not self._ensure_generated():
            return 1
        if self._run_root_make("generate_hashes"):
            os.environ["ACE_HASHES_READY"] = "1"
        if not self.check_loader_epoch():
            return 1
        out = Path(args[0]).expanduser().resolve() if args else self.ace_root / "dist"
        out.mkdir(parents=True, exist_ok=True)
        for old in out.iterdir():
            if old.is_file():
                old.unlink()
        mods = sorted(set(self._all_manifests()) | set(self._defaulted_modules()))
        taken, stale = 0, []
        for mod in mods:
            art = self._bin_dir() / f"{mod}.{self._lib_ext()}"
            if not art.is_file():
                continue
            if not self._module_current(mod, False):
                stale.append(art.name)
                continue
            shutil.copy2(art, out / art.name)
            taken += 1
        release = self._release_store([]) / ("etcs.exe" if platform.system() == "Windows" else "etcs")
        if release.is_file():
            shutil.copy2(release, out / release.name)
        else:
            print(f"{YELLOW}[!] no release to publish ({release}); `ace release` first. "
                  f"The list will name modules only.{RESET}")
        if stale:
            print(f"{YELLOW}[!] not published, older than the tree ({len(stale)}): {' '.join(stale)}{RESET}")
        try:
            p = subprocess.run([str(signer), "--manifest", str(out), str(out / "manifest")],
                               capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=300)
        except (OSError, subprocess.TimeoutExpired) as e:
            print(f"{RED}[-] bin/etcs --manifest: {e}{RESET}")
            return 1
        for line in (p.stderr or "").splitlines():
            if line.startswith("etcs: "):
                print(f"{YELLOW}[!] {line[6:]}{RESET}")
        if p.returncode == 2 or not (out / "manifest").is_file():
            print(f"{RED}[-] no list written.{RESET}")
            return 1
        listed = sum(1 for l in (out / "manifest").read_text().splitlines()
                     if l and not l.startswith(("etcs-dist ", "etcs-dist-sig ")))
        print(f"{GREEN}[+] published {listed} binaries to {out} for epoch {self.epoch_id()[:12]}{RESET}")
        print(f"{DIM}    the site reads it at start (site_pki.etcs mounts it at /dist){RESET}")
        return 0 if p.returncode == 0 else 1


    # ------------------------------------------------------------------
    # The root, and a machine with nothing but etcs
    # ------------------------------------------------------------------

    def pin(self, args):
        """ace pin <root.cert | 64 hex | clear>: write manifests/root.pub. The
        next build is in that root's epoch -- the guild, once it is ACE's."""
        from .ace_generate import ROOT_PIN_FILE
        if len(args) != 1:
            print("Usage: ace pin <root.cert | key hex | clear>")
            return 1
        f = self.tool_root / ROOT_PIN_FILE
        if args[0] == "clear":
            f.unlink(missing_ok=True)
            print(f"{GREEN}[+] no root pinned: loaders built now are an experimental epoch's{RESET}")
            return 0
        text = args[0].strip().lower()
        if not _HEX64.match(text):
            try:
                raw = Path(args[0]).read_text().strip()
                b = bytes.fromhex(raw)
            except (OSError, ValueError):
                print(f"{RED}[-] {args[0]} is neither a key nor a certificate file{RESET}")
                return 1
            # "ETCSCRT1" | role u8 | subject[32] | issuer[32] ...; a root is role 1, its own issuer.
            if len(b) < 73 or b[:8] != b"ETCSCRT1" or b[8] != 1 or b[9:41] != b[41:73]:
                print(f"{RED}[-] {args[0]} is not a root certificate{RESET}")
                return 1
            text = b[9:41].hex()
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text + "\n")
        print(f"{GREEN}[+] pinned root {text}{RESET}")
        print(f"{DIM}    the next build is that root's epoch: `ace make modules && ace make loader etcs`{RESET}")
        return 0

    def bundle(self, args):
        """ace bundle <dir> [module...]: bin/etcs and the named modules (the
        ceremony's by default) in <dir>/bin, with every module script beside
        them, for a machine that has nothing else. bin/etcs carries its
        builder's key, so it takes those modules with no keystore there."""
        if not args:
            print("Usage: ace bundle <dir> [module...]")
            return 1
        signer = self._signer()
        if not signer:
            print(f"{RED}[-] there is no bin/etcs to bundle. `ace make loader etcs` first.{RESET}")
            return 1
        p = subprocess.run([str(signer), "--attest"], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=120)
        builder = next((l.split()[1] for l in p.stdout.splitlines() if l.startswith("builder ")), None)
        if not builder:
            print(f"{RED}[-] bin/etcs was built with no builder key, so where nothing else is it would "
                  f"take none of its modules. `ace make loader etcs` again.{RESET}")
            return 1
        out = Path(args[0]).expanduser().resolve()
        mods = args[1:] or ["CryptProvider", "NetworkProvider", "ShellProvider"]
        (out / "bin").mkdir(parents=True, exist_ok=True)
        shutil.copy2(signer, out / "bin" / signer.name)
        for mod in mods:
            art = self._bin_dir() / f"{mod}.{self._lib_ext()}"
            if not art.is_file():
                print(f"{RED}[-] no {art.name} in bin/{RESET}")
                return 1
            shutil.copy2(art, out / "bin" / art.name)
        for scripts in sorted((self.ace_root / "modules").glob("*/scripts")):
            if scripts.parent.name in mods:
                dest = out / "modules" / scripts.parent.name / "scripts"
                dest.mkdir(parents=True, exist_ok=True)
                for f in scripts.glob("*.etcs"):
                    shutil.copy2(f, dest / f.name)
        print(f"{GREEN}[+] bundled bin/etcs and {', '.join(mods)} in {out}{RESET}")
        print(f"{DIM}    builder {builder[:12]}; run there as: ACE_ROOT={out} {out}/bin/etcs <script>{RESET}")
        return 0
