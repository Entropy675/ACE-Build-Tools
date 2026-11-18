"""ace sign -- every module binary carries the chain that lets a loader load it.

    ace sign            sign every current module artifact in bin/ and bin/wasm/,
                        and the native loader binaries in bin/

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
_LINEAGE = re.compile(r"^etcs-lineage 1 ")

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

    def _ask_loader(self, signer, *args, want=_HEX64):
        """(returncode, the answer line or None, stderr). The loader logs to
        stdout as it starts and stops; the answer is the line that matches
        `want` -- by default, one that is nothing but a key or an epoch."""
        # stdin closed and a timeout: a bin/etcs from before signing reads
        # "--sign" as a script it cannot open and falls into its REPL.
        try:
            p = subprocess.run([str(signer), *args], capture_output=True, text=True,
                               stdin=subprocess.DEVNULL, timeout=120)
        except subprocess.TimeoutExpired:
            return 2, None, "bin/etcs did not answer -- it predates signing; `ace make loader etcs`"
        except OSError as e:
            return 2, None, str(e)
        if "cannot open script file '--" in (p.stderr or ""):
            return 2, None, "bin/etcs predates signing; `ace make loader etcs` and it signs these"
        line = next((l.strip() for l in p.stdout.splitlines() if want.match(l.strip())), None)
        return p.returncode, line, (p.stderr or "").strip()

    def builder_key(self):
        """(key, why). The native loader's public key, made and registered on
        first use -- the loader a web loader built here takes Loader-signed
        modules from (ETCS_BUILDER_KEY)."""
        return self._loader_answer("--loader-key")

    def root_key(self):
        """(key, why). The root the native loader's registration ends at. While
        ACE's own root is unset that is a temporary root in the loader's store,
        which a browser cannot read, so a web loader is told it at link time
        (ETCS_TEMP_ROOT_KEY)."""
        return self._loader_answer("--root")

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

    def _sign_one(self, signer, mod, art, epoch, verb="--sign"):
        """'signed', 'unchanged', or why not. With --succeed, also the lineage
        edge the signer recorded (or None): (result, edge)."""
        with tempfile.TemporaryDirectory(prefix="ace-sign-") as d:
            out = Path(d) / "chain"
            rc, edge, err = self._ask_loader(signer, verb, mod, str(art), epoch, str(out), want=_LINEAGE)
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
                    result, edge = self._sign_one(signer, "etcs", new, epoch, verb="--succeed")
                    by = who
                    if result in ("signed", "unchanged"):
                        break
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
        self._ensure_generated()
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
