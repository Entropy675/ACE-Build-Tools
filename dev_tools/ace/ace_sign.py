"""ace sign -- every module binary carries the chain that lets a loader load it.

    ace sign            sign every current module artifact in bin/ and bin/wasm/,
                        and the native loader binaries in bin/
    ace identity [<hex> | store | none]
                        the identity every loader built here is compiled with:
                        by default this store's own (bin/etcs --identity)
    ace mint <witnessed> <statement>... [quorum=N] [--out <dir>]
                        the minting server signs a witnessed build, the loader
                        among it too, with the marketplace key: what the site serves
    ace publish [dir] [--from <minted>]
                        what the site serves at /dist: the minted binaries, and
                        the marketplace's signed list of them
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
_LINEAGE = re.compile(r"^etcs-lineage [123] ")

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

    # ------------------------------------------------------------------
    # The identity a loader built here is compiled with
    # ------------------------------------------------------------------
    #
    # The fold along a registration to the key that builds (core/Trust.h): what
    # that builder is authorized to build with, and what every loader it builds
    # requires at the head of what it takes globally. Not a header, so no
    # epoch: builders of every identity share one. By default it is this
    # store's own, which bin/etcs answers; `ace identity <hex>` builds for
    # another's -- a witness for the minting server's, a developer whose loader
    # should take what the site serves -- and `none` for no identity at all.
    # $ACE_IDENTITY, while set, wins.

    def _identity_cache_path(self):
        return self._root_cache_path().with_name("etcs_identity")

    def _identity_setting(self):
        env = os.environ.get("ACE_IDENTITY", "").strip().lower()
        if env:
            return env, "$ACE_IDENTITY"
        try:
            text = self._identity_cache_path().read_text().strip().lower()
        except OSError:
            text = ""
        return (text or "store"), ("ace identity" if text else "the default")

    def build_identity(self):
        """(hex or None, where it came from)."""
        setting, source = self._identity_setting()
        if setting == "none":
            return None, source + ": none"
        if _HEX64.match(setting):
            return setting, source
        ident, why = self._loader_answer("--identity")
        return ident, ("this store's own" if ident else why)

    def identity_cmd(self, args):
        """ace identity [<hex> | store | none]: what loaders built here are
        compiled with, or set it."""
        if len(args) > 1 or (args and args[0] not in ("store", "none") and not _HEX64.match(args[0].lower())):
            print("Usage: ace identity [<64 hex> | store | none]")
            return 1
        if args:
            f = self._identity_cache_path()
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(args[0].lower() + "\n")
        ident, source = self.build_identity()
        print(f"{ident or 'none'}  ({source})")
        if os.environ.get("ACE_IDENTITY") and args:
            print(f"{YELLOW}[!] ACE_IDENTITY is set, and wins while it is{RESET}")
        if args:
            print(f"{DIM}    the next loader build is built with it: `ace make loader etcs`{RESET}")
        return 0

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
    # (core/Trust.h), and the next etcs is passed off by the one going out: ace
    # keeps a copy of bin/etcs before a loader build replaces it, and that copy
    # signs its successor and the pass-off into it. Where there is no outgoing
    # loader, or what it signs does not attest the new one, the new one passes
    # itself off: a lineage beginning, which a loader of no identity, or of its
    # own key's, takes -- and one built for a minted identity does not: there a
    # lineage begins at a mint (`ace mint`, or the site's etcs as bin/etcs), and
    # the build after it is passed off by the minted loader. Every other loader
    # binary (the Run_* testers) is passed off by the new etcs.

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
                # A signature the new loader does not take -- the outgoing one was
                # built for another identity -- is no attestation.
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
                        if "mint" in line:
                            print(f"{DIM}    it runs with a warning, and signs its local half alone. Under a minted "
                                  f"identity a lineage begins at a mint: the site's etcs as bin/etcs, then build "
                                  f"again.{RESET}")
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
                result, _ = self._sign_one(new, name, art, epoch, verb="--succeed")
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
    # Minting: the marketplace key over a witnessed build
    # ------------------------------------------------------------------
    #
    # Builders of lower trust run the build first (`ace witness`, built for the
    # minting server's identity), and only bytes they agree on are minted: the
    # minting server's loader -- its store registered as the marketplace --
    # checks the consensus, then signs those exact bytes, modules and the
    # loader alike. A loader binary the marketplace signed is minted: it
    # attests on any machine built for that identity, with an empty store, and
    # a lineage there begins at it.

    @staticmethod
    def _statement_head(path):
        """The first line of a witness statement, as {key: value}."""
        try:
            first = Path(path).read_text().splitlines()[0].split()
        except (OSError, IndexError):
            return None
        if first[:2] != ["etcs-witness", "1"]:
            return None
        return dict(kv.split("=", 1) for kv in first[2:] if "=" in kv)

    def mint(self, args):
        out = None
        if "--out" in args:
            i = args.index("--out")
            if i + 1 >= len(args):
                args = []
            else:
                out = Path(args[i + 1]).expanduser().resolve()
                args = args[:i] + args[i + 2:]
        quorum = [a for a in args if a.startswith("quorum=")]
        args = [a for a in args if not a.startswith("quorum=")]
        if len(args) < 2:
            print("Usage: ace mint <witnessed dir> <statement>... [quorum=N] [--out <dir>]")
            return 1
        src = Path(args[0]).expanduser().resolve()
        statements = [str(Path(a).expanduser().resolve()) for a in args[1:]]
        out = out or self.ace_root / "minted"
        signer = self._signer()
        if not signer:
            print(f"{RED}[-] there is no bin/etcs to mint with. `ace make loader etcs` first.{RESET}")
            return 1
        p = subprocess.run([str(signer), "--attest"], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=120)
        if not re.search(r"^key\s+[0-9a-f]{64} \(marketplace, proven\)$", p.stdout, re.M):
            print(f"{RED}[-] this store is not the minting server's: its key is not registered as the "
                  f"marketplace, or the keystore does not hold it.{RESET}")
            return 1
        rc, ident, err = self._ask_loader(signer, "--identity")
        if rc != 0 or not ident:
            print(f"{RED}[-] bin/etcs gave no identity: {err or 'no answer'}{RESET}")
            return 1

        # The builders agree on these bytes, or nothing is minted.
        c = subprocess.run([str(signer), "--consensus", *quorum, f"check={src}", *statements],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=300)
        for line in c.stdout.splitlines():
            if not line.startswith("["):                   # the loader's own log
                print(f"    {line}")
        if c.returncode != 0:
            print(f"{RED}[-] not minted: {src} is not the witnesses' consensus build{RESET}")
            return 1
        heads = [self._statement_head(s) for s in statements]
        built_for = {(h or {}).get("identity", "none") for h in heads}
        if built_for != {ident}:
            print(f"{RED}[-] not minted: the witnesses built for identity {', '.join(sorted(built_for))}, "
                  f"and this server mints {ident}. `ace witness <out> --identity {ident}`{RESET}")
            return 1
        epoch = heads[0].get("epoch")

        suffix = ".exe" if platform.system() == "Windows" else ""
        exts = (".so", ".dll", ".wasm", ".exe")
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True)
        minted, left = 0, 0
        for art in sorted(src.iterdir()):
            if not art.is_file() or art.name.startswith("witness-"):
                continue
            name = next((art.name[:-len(e)] for e in exts if art.name.endswith(e)), art.name)
            dest = out / art.name
            shutil.copy2(art, dest)
            kernel = name == "etcs"
            r = self._sign_one(signer, name, dest, epoch, verb="--succeed" if kernel else "--sign")
            result = r[0] if kernel else r
            if result in ("signed", "unchanged"):
                minted += 1
            else:
                left += 1
                print(f"{RED}[-] {art.name} is not minted -- {result}{RESET}")
        etcs = out / ("etcs" + suffix)
        if etcs.is_file():
            with tempfile.TemporaryDirectory(prefix="ace-mint-") as empty:
                try:
                    a = subprocess.run([str(etcs), "--attest"], capture_output=True, text=True,
                                       stdin=subprocess.DEVNULL, timeout=120,
                                       env={**os.environ, "ETCS_STORE": empty})
                    line = next((l for l in a.stdout.splitlines() if l.startswith("attested")), "")
                    if a.returncode != 0:
                        left += 1
                        print(f"{RED}[-] the minted etcs does not attest on an empty store -- "
                              f"{line.split(':', 1)[-1].strip() or 'no answer'}{RESET}")
                    else:
                        print(f"{DIM}    the minted etcs attests on an empty store{RESET}")
                except OSError:
                    print(f"{DIM}    the minted etcs is another machine's: not run here{RESET}")
        if left:
            print(f"{RED}[-] {left} not minted; {out} is incomplete{RESET}")
            return 1
        print(f"{GREEN}[+] minted {minted} binaries into {out} for identity {ident[:12]}{RESET}")
        print(f"{DIM}    then: ace publish [<dir>] --from {out}{RESET}")
        return 0


    # ------------------------------------------------------------------
    # What the site serves at /dist
    # ------------------------------------------------------------------
    #
    # What `ace mint` made (<ACE_ROOT>/minted, or --from), and bin/etcs
    # --manifest's list of it: the marketplace's signature over each one's
    # digest and epochs, and over the epoch the site is in. With nothing minted,
    # the current modules and bin/etcs, as the minting server built them. A
    # loader reads the list (CryptProvider::Upstream) and fetches what it is
    # behind on. What a download would not take -- what does not come to the
    # identity bin/etcs is built with -- is left off by the loader, and said.

    def publish(self, args):
        source = None
        if "--from" in args:
            i = args.index("--from")
            if i + 1 >= len(args):
                print("Usage: ace publish [<dir>] [--from <minted>]")
                return 1
            source = Path(args[i + 1]).expanduser().resolve()
            args = args[:i] + args[i + 2:]
        if len(args) > 1:
            print("Usage: ace publish [<dir>] [--from <minted>]")
            return 1
        if source is None and (self.ace_root / "minted").is_dir():
            source = self.ace_root / "minted"
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
        stale = []
        if source:
            if not source.is_dir():
                print(f"{RED}[-] {source} is not a directory{RESET}")
                return 1
            for art in sorted(source.iterdir()):
                if art.is_file():
                    shutil.copy2(art, out / art.name)
            print(f"{DIM}    from {source}{RESET}")
        else:
            mods = sorted(set(self._all_manifests()) | set(self._defaulted_modules()))
            for mod in mods:
                art = self._bin_dir() / f"{mod}.{self._lib_ext()}"
                if not art.is_file():
                    continue
                if not self._module_current(mod, False):
                    stale.append(art.name)
                    continue
                shutil.copy2(art, out / art.name)
            shutil.copy2(signer, out / signer.name)
            print(f"{YELLOW}[!] nothing minted ({self.ace_root / 'minted'}): publishing this server's own "
                  f"build. `ace mint` publishes what witnesses agreed on.{RESET}")
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
    # A machine with nothing but etcs
    # ------------------------------------------------------------------

    def bundle(self, args):
        """ace bundle <dir> [--from <built>] [module...]: bin/etcs and the named
        modules (the ceremony's by default) in <dir>/bin, with every module
        script beside them, for a machine that has nothing else. bin/etcs
        carries its builder's key, so it takes those modules with no keystore
        there. --from takes them from a witnessed build instead (ace witness
        <out>: <out>/a), which carries no builder key: the machine then signs
        its modules under a keystore of its own before it can load them."""
        source = None
        if "--from" in args:
            i = args.index("--from")
            if i + 1 >= len(args):
                print("Usage: ace bundle <dir> [--from <built>] [module...]")
                return 1
            source = Path(args[i + 1]).expanduser().resolve()
            args = args[:i] + args[i + 2:]
        if not args:
            print("Usage: ace bundle <dir> [--from <built>] [module...]")
            return 1
        suffix = ".exe" if platform.system() == "Windows" else ""
        signer = (source / ("etcs" + suffix)) if source else self._signer()
        if not signer or not signer.is_file():
            print(f"{RED}[-] there is no etcs to bundle{' in ' + str(source) if source else ''}. "
                  f"`ace make loader etcs` first.{RESET}")
            return 1
        p = subprocess.run([str(signer), "--attest"], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=120)
        builder = next((l.split()[1] for l in p.stdout.splitlines() if l.startswith("builder ")), None)
        if not builder and not source:
            print(f"{RED}[-] bin/etcs was built with no builder key, so where nothing else is it would "
                  f"take none of its modules. `ace make loader etcs` again.{RESET}")
            return 1
        out = Path(args[0]).expanduser().resolve()
        mods = args[1:] or ["CryptProvider", "NetworkProvider", "ShellProvider"]
        (out / "bin").mkdir(parents=True, exist_ok=True)
        shutil.copy2(signer, out / "bin" / signer.name)
        for mod in mods:
            art = (source or self._bin_dir()) / f"{mod}.{self._lib_ext()}"
            if not art.is_file():
                print(f"{RED}[-] no {art.name} in {source or 'bin/'}{RESET}")
                return 1
            shutil.copy2(art, out / "bin" / art.name)
        for scripts in sorted((self.ace_root / "modules").glob("*/scripts")):
            if scripts.parent.name in mods:
                dest = out / "modules" / scripts.parent.name / "scripts"
                dest.mkdir(parents=True, exist_ok=True)
                for f in scripts.glob("*.etcs"):
                    shutil.copy2(f, dest / f.name)
        print(f"{GREEN}[+] bundled bin/etcs and {', '.join(mods)} in {out}{RESET}")
        if builder:
            print(f"{DIM}    builder {builder[:12]}; run there as: ACE_ROOT={out} {out}/bin/etcs <script>{RESET}")
        else:
            print(f"{YELLOW}[!] this etcs has no builder key: it takes these modules only once a key of the "
                  f"machine's own has signed them, under a keystore session there.{RESET}")
        return 0

    # ------------------------------------------------------------------
    # Witnesses: what this machine's builds of this tree come to
    # ------------------------------------------------------------------
    #
    # Built twice from scratch, each binary compared by the digest a loader
    # checks, and the agreement written as a statement by the loader that was
    # built (core/Trust.h, --witness). Statements from several machines are
    # agreed on with `bin/etcs --consensus`. The loader is built with no
    # builder key -- that key is compiled in and is each machine's own -- so
    # what one machine builds is what another can.

    _WITNESS_MODULES = ("CryptProvider", "NetworkProvider", "ShellProvider")

    @staticmethod
    def _tree_word(repo):
        """A tree's commit, and the hash of what differs from it, or None."""
        g = lambda *a: subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True)
        head = g("rev-parse", "HEAD")
        if head.returncode != 0:
            return None
        word = head.stdout.strip()
        diff = g("diff", "HEAD", "--binary", "--ignore-submodules=all").stdout
        if diff:
            word += "+" + hashlib.sha256(diff.encode()).hexdigest()[:12]
        return word

    def _build_account(self):
        """What this tree was built from, as the statement's key=values: the
        three commits, the path (it is compiled into the loader) and the
        compiler. Compared by --consensus, which names the ones that differ."""
        about = {"commit": self._tree_word(self.ace_root), "commons": self._tree_word(self.ace_root / "modules"),
                 "tools": self._tree_word(self.tool_root), "path": str(self.ace_root)}
        cc = subprocess.run(["g++", "--version"], capture_output=True, text=True)
        about["cc"] = "_".join((cc.stdout.splitlines() or ["unknown"])[0].split())
        return {k: v for k, v in about.items() if v}

    def witness(self, args):
        """ace witness <out> [--identity <hex>] [module...]: build bin/etcs and
        the modules (the ceremony's by default) twice from scratch into <out>/a
        and <out>/b, and have the loader built write
        <out>/witness-<host>-<arch>.txt. The loader is built for the identity
        given -- the minting server's, for a build it will mint -- or for none;
        never this machine's own, which is no other witness's."""
        ident = None
        if "--identity" in args:
            i = args.index("--identity")
            if i + 1 >= len(args) or not _HEX64.match(args[i + 1].lower()):
                print("Usage: ace witness <out> [--identity <64 hex>] [module...]")
                return 1
            ident = args[i + 1].lower()
            args = args[:i] + args[i + 2:]
        if not args:
            print("Usage: ace witness <out> [--identity <64 hex>] [module...]")
            return 1
        out = Path(args[0]).expanduser().resolve()
        mods = args[1:] or list(self._WITNESS_MODULES)
        suffix = ".exe" if platform.system() == "Windows" else ""
        ext = self._lib_ext()
        for run in ("a", "b"):
            print(f"{CYAN}[*] witness: build {run} of {', '.join(mods)} and etcs{RESET}")
            for mod in mods:
                if self.make(["module", mod, "--force"]):
                    print(f"{RED}[-] {mod} did not build{RESET}")
                    return 1
            if self.make(["loader", "etcs", "--force", "-UETCS_BUILDER_KEY",
                          f"-DETCS_IDENTITY={ident}" if ident else "-UETCS_IDENTITY"]):
                print(f"{RED}[-] etcs did not build{RESET}")
                return 1
            d = out / run
            shutil.rmtree(d, ignore_errors=True)
            d.mkdir(parents=True)
            for name in [f"{m}.{ext}" for m in mods] + ["etcs" + suffix]:
                art = self._bin_dir() / name
                if not art.is_file():
                    print(f"{RED}[-] no bin/{name} after build {run}{RESET}")
                    return 1
                shutil.copy2(art, d / name)
        account = self._build_account()
        account["identity"] = ident or "none"
        host = re.sub(r"[^A-Za-z0-9._-]", "", platform.node()) or "unnamed"
        arch = f"{platform.system().lower()}-{platform.machine().lower()}"
        statement = out / f"witness-{host}-{arch}.txt"
        loader = out / "a" / ("etcs" + suffix)
        p = subprocess.run([str(loader), "--witness", str(out / "a"), str(out / "b"), str(statement),
                            *[f"{k}={v}" for k, v in account.items()]],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=300)
        for line in p.stdout.splitlines():
            if re.match(r"^(\S+ [0-9a-f]{64}|\S+ differs|\S+ is not|witness |witnessed )", line):
                print(f"    {line}")
        if p.returncode != 0:
            print(f"{RED}[-] {(p.stderr or 'the loader wrote no statement').strip().splitlines()[-1]}{RESET}")
            return 1
        print(f"{GREEN}[+] {statement}{RESET}")
        print(f"{DIM}    agree several: bin/etcs --consensus [quorum=N] [check=<dir>] <statement>...{RESET}")
        return 0

    # ------------------------------------------------------------------
    # The source, for machines with no network
    # ------------------------------------------------------------------
    #
    # This tree, Commons and ACE-Build-Tools, each with its .git (a vendored
    # dependency is a submodule checkout the module Makefiles resolve by
    # commit, locally), and the Monocypher pin's cache: one tar a machine with
    # nothing on it builds from. The same inputs make the same bytes, so its
    # SHA-256 is what every witness checks before unpacking.

    def source(self, args):
        """ace source <dir>: <dir>/etcs-source-<commit>.tar and its .sha256."""
        import tarfile
        from .ace_generate import MONOCYPHER_COMMIT
        if len(args) != 1:
            print("Usage: ace source <dir>")
            return 1
        out = Path(args[0]).expanduser().resolve()
        out.mkdir(parents=True, exist_ok=True)
        word = (self._tree_word(self.ace_root) or "unknown")[:20]
        tar_path = out / f"etcs-source-{word}.tar"

        def entries(repo, prefix):
            """Every file each repository under `repo` tracks, and every .git,
            as (path on disk, path in the tar), in order. Each nested checkout
            -- Commons, a vendored submodule -- is asked for its own files."""
            paths = set()
            for root, dirs, files in os.walk(repo):
                rel = Path(root).relative_to(repo)
                if ".git" in dirs or ".git" in files:
                    ls = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True)
                    paths.update(str(rel / f) for f in ls.stdout.decode().split("\0") if f)
                    g = Path(root) / ".git"
                    if g.is_dir():                          # git wants its empty dirs too
                        for r2, d2, f2 in os.walk(g):
                            paths.update(str((Path(r2) / f).relative_to(repo)) for f in d2 + f2)
                    else:
                        paths.add(str(rel / ".git"))
                dirs[:] = [d for d in dirs if d != ".git"]
            return [(repo / p, f"{prefix}/{p}") for p in sorted(paths)
                    if (repo / p).is_symlink() or (repo / p).is_file() or (repo / p).is_dir()]

        cache = self._get_registry_dir() / "cache" / ("monocypher-" + MONOCYPHER_COMMIT[:12])
        if not (cache / "src" / "monocypher.c").is_file():
            self._monocypher_tree()
        unpack = (
            "#!/bin/sh\n"
            "# Unpack anywhere, and that is this machine's ACE_ROOT: the tree is <dir>/ETCS.\n"
            "#     mkdir -p <dir> && tar -xf etcs-source-*.tar -C <dir> && sh <dir>/unpack.sh\n"
            "# The root is compiled into the loader, so witnesses that chose one root\n"
            "# agree with each other, and a witness at another root is a group of its own.\n"
            "set -e\n"
            "here=$(cd \"$(dirname \"$0\")\" && pwd)\n"
            "mkdir -p \"$HOME/.etcs_registry/cache\"\n"
            "cp -a \"$here/registry-cache/.\" \"$HOME/.etcs_registry/cache/\"\n"
            "python3 \"$here/ACE-Build-Tools/ace_install.py\" root \"$here/ETCS\"\n"
            "echo \"ace: python3 $here/ACE-Build-Tools/ace_install.py\"\n").encode()

        def add(t, disk, name, data=None):
            info = tarfile.TarInfo(name)
            info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
            if data is None and disk.is_symlink():          # tracked as a link, kept one
                info.type, info.linkname, info.mode = tarfile.SYMTYPE, os.readlink(disk), 0o777
                t.addfile(info)
            elif data is None and disk.is_dir():
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                t.addfile(info)
            elif data is None:
                st = disk.stat()
                info.size, info.mode = st.st_size, 0o755 if st.st_mode & 0o111 else 0o644
                with open(disk, "rb") as f:
                    t.addfile(info, f)
            else:
                info.size, info.mode = len(data), 0o755
                import io
                t.addfile(info, io.BytesIO(data))

        print(f"[*] collecting the trees ...")
        files = (entries(self.ace_root, "ETCS") + entries(self.tool_root, "ACE-Build-Tools")
                 + [(p, f"registry-cache/{cache.name}/{p.relative_to(cache)}")
                    for p in sorted(cache.rglob("*"))])
        with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as t:
            add(t, None, "unpack.sh", unpack)
            for disk, name in files:
                add(t, disk, name)
        digest = hashlib.sha256()
        with open(tar_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
        (out / (tar_path.name + ".sha256")).write_text(f"{digest.hexdigest()}  {tar_path.name}\n")
        size = tar_path.stat().st_size / (1 << 20)
        print(f"{GREEN}[+] {tar_path} ({size:.0f} MiB, {len(files)} files){RESET}")
        print(f"{DIM}    sha256 {digest.hexdigest()}{RESET}")
        print(f"{DIM}    there: mkdir -p <dir> && tar -xf {tar_path.name} -C <dir> && sh <dir>/unpack.sh "
              f"(<dir>/ETCS is that machine's ACE_ROOT){RESET}")
        return 0
