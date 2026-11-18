"""ace generate -- source files ETCS builds from but does not keep in git.

    ace deps generate

Each target is regenerated from a pinned source and written only when its
bytes would change, so a regeneration is a no-op on an unchanged tree and the
file's entry in the global hash headers (core_hashes.h, libs_hashes.h) is a
function of the pin alone.

DETERMINISM IS THE CONTRACT. Every generated file is hashed into the epoch,
and a module and loader that disagree on one byte refuse each other. So the
provenance header records WHEN in terms of the source -- the pinned commit
and its commit date, or the generator's own inputs -- never the wall clock of
the run. Two machines regenerating the same pin produce the same bytes.

Targets:
    core/AirtyMacros_Generated.h  from dev_tools/generate_airty_macros.py
    libs/monocypher.h             from Monocypher at a pinned commit,
                                  amalgamated into one stb-style header
    core/AceIdentity.h            from the pin (manifests/root.pub): ACE's
                                  identity at its shortest, the root every
                                  chain ACE attests ends at
"""
from pathlib import Path
import hashlib
import importlib.util
import re
import subprocess

from .ace_common import GREEN, YELLOW, RED, RESET, DIM

# Bump when the shape of anything this file writes changes; it is printed in
# every provenance header, so a format change is visible as a source change.
GENERATOR_VERSION = 1

# ---------------------------------------------------------------- Monocypher
MONOCYPHER_URL    = "https://github.com/LoupVaillant/Monocypher.git"
MONOCYPHER_COMMIT = "907e90ddd4c78f02e0d49e90384e4197f7dcdf26"
MONOCYPHER_DATE   = "2026-11-01T21:03:14+01:00"
# The commit pins the tree; these pin the four files actually read, so a fetch
# that resolves to anything else (a rewritten ref, a corrupted cache) refuses.
MONOCYPHER_FILES = {
    "src/monocypher.h":
        "71cd068106248b4d843660fa78349193f04bbf75be6a9016ea122e354e169acf",
    "src/monocypher.c":
        "c1736a22e2ebb7ef3bdad7cc972050f038ce36ce5fc5448de08d7a4c6a379e7f",
    "src/optional/monocypher-ed25519.h":
        "4e9ff4ab3be24f3be13a15ca28e1ad67153645bf96e947d7fe719f2e0400cfd8",
    "src/optional/monocypher-ed25519.c":
        "b3ad4a2dce24dca40d2235a3c614ee996071caa32517d49805ad7159ef8238ae",
    "LICENCE.md":
        "a5781770269d2516e52ba4863f790c10a16da4089a1e81823aee19ff1e9026b0",
}
MONOCYPHER_PURPOSE = ("Ed25519 (RFC 8032, SHA-512) for the loader's module "
                      "signature chain and CryptProvider.")


# ---------------------------------------------------------------- ACE's root
# The super-root's public key, 64 hex digits: manifests/root.pub, which `ace
# pin` writes from the ceremony's root.cert. This is where it enters a build:
# compiled into every loader as the one root a chain may end at (core/Trust.h),
# and, being a core header, hashed into the epoch -- a build for another root is
# another epoch, and a build with none is an experimental one.
#
# ACE_ROOT_KEY is read only when there is no file.
ACE_ROOT_KEY = ""
ROOT_PIN_FILE = "manifests/root.pub"


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _provenance(source, when, purpose, extra=()):
    lines = [
        "// GENERATED FILE -- do not edit; regenerate with `ace deps generate`.",
        "// Generator: ACE-Build-Tools dev_tools/ace/ace_generate.py (v%d)" % GENERATOR_VERSION,
        "// Source:    %s" % source,
        "// When:      %s" % when,
        "// Purpose:   %s" % purpose,
    ]
    lines += [("// %s" % e) if e else "//" for e in extra]
    return "\n".join(lines) + "\n"


def _defined_macros(text):
    """Object- and function-like macro names a .c file #defines at file scope,
    in first-definition order, so the amalgamation can #undef them after the
    section and not leak FOR / MIN / COPY into the including translation unit."""
    seen, out = set(), []
    for m in re.finditer(r"^#define\s+([A-Za-z_][A-Za-z0-9_]*)", text, re.M):
        if m.group(1) not in seen:
            seen.add(m.group(1))
            out.append(m.group(1))
    return out


def _strip_local_includes(text):
    return re.sub(r'^#include\s+"monocypher(-ed25519)?\.h"\s*\n', "", text, flags=re.M)


class GenerateMixin:

    # ------------------------------------------------------------ plumbing
    def _generated_targets(self):
        """(relative output path, producer) for every generated file."""
        return [
            ("core/AirtyMacros_Generated.h", self._gen_airty_macros),
            ("libs/monocypher.h",            self._gen_monocypher),
            ("core/AceIdentity.h",           self._gen_ace_identity),
        ]

    # Generated once, and named otherwise since: a core header is hashed into
    # the epoch, so one left behind would put this tree in an epoch of its own.
    _RETIRED_TARGETS = ("core/AceRoot.h",)

    def _write_if_changed(self, path, content):
        data = content.encode("utf-8")
        try:
            if path.read_bytes() == data:
                return False
        except OSError:
            pass
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)
        return True

    def generate_all(self, quiet=False):
        """Regenerate every target. True when all succeeded. Writes only on a
        byte change, so mtimes -- and therefore make -- stay quiet otherwise."""
        ok = True
        for rel in self._RETIRED_TARGETS:
            old = self.ace_root / rel
            if old.is_file():
                old.unlink()
                print(f"  [*] {rel}: {YELLOW}removed{RESET}  {DIM}retired{RESET}")
        for rel, producer in self._generated_targets():
            out = self.ace_root / rel
            try:
                content = producer()
            except Exception as e:                      # noqa: BLE001 -- report and continue
                print(f"  {RED}[-] {rel}: {e}{RESET}")
                ok = False
                continue
            changed = self._write_if_changed(out, content)
            if not quiet or changed:
                state = f"{GREEN}written{RESET}" if changed else f"{DIM}unchanged{RESET}"
                print(f"  [*] {rel}: {state}  {DIM}sha256 {_sha256(content.encode())[:16]}{RESET}")
        return ok

    def _ensure_generated(self):
        """Build-time gate: cheap when nothing changed (one compare per file,
        no network once the Monocypher pin is cached). False stops the build:
        libs/ and core/ are hashed into the epoch, so a tree missing a
        generated file would build an epoch no other machine shares -- a
        refusal at load time that reads like a version skew, not a missing
        file."""
        if self.generate_all(quiet=True):
            return True
        print(f"{RED}[-] Generated sources incomplete; the epoch would differ from "
              f"every other build. Fix the error above, then 'ace deps generate'.{RESET}")
        return False

    # ----------------------------------------------------------- ACE's root
    def root_pin(self):
        """The pinned root, lower-case hex, or "" while there is none."""
        f = self.tool_root / ROOT_PIN_FILE
        key = (f.read_text() if f.is_file() else ACE_ROOT_KEY).strip().lower()
        if key and not re.fullmatch(r"[0-9a-f]{64}", key):
            raise RuntimeError("ACE_ROOT_KEY is not 64 hex digits")
        return "" if key == "0" * 64 else key

    def _gen_ace_identity(self):
        key = self.root_pin()
        head = _provenance(
            "ACE-Build-Tools " + ROOT_PIN_FILE + " (ace pin)",
            "n/a -- a pure function of the pin",
            "ACE's identity at its shortest: the root every chain ACE attests ends at (core/Trust.h).",
            extra=["", "All zero: no root is pinned, and a loader built so is an experimental epoch's."])
        return (head
                + "#ifndef ETCS_CORE_ACEIDENTITY_H__\n#define ETCS_CORE_ACEIDENTITY_H__\n\n"
                + '#define ETCS_ACE_IDENTITY_ROOT "%s"\n\n' % (key or "0" * 64)
                + "#endif // ETCS_CORE_ACEIDENTITY_H__\n")

    # ------------------------------------------------------- AirtyMacros
    def _gen_airty_macros(self):
        script = self.tool_root / "dev_tools" / "generate_airty_macros.py"
        spec = importlib.util.spec_from_file_location("ace_generate_airty", script)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        body = mod.generate(mod.MAX_ARITY)
        head = _provenance(
            "ACE-Build-Tools dev_tools/generate_airty_macros.py, MAX_ARITY=%d" % mod.MAX_ARITY,
            "n/a -- a pure function of the generator's inputs above",
            "Fixed-arity FOR_EACH / dispatch-select macros behind ETCS_API.h.")
        return head + body

    # --------------------------------------------------------- Monocypher
    def _monocypher_tree(self):
        """The pinned checkout, fetched once into the registry cache by commit
        (not by tag or branch, so nothing upstream can move it)."""
        cache = self._get_registry_dir() / "cache" / ("monocypher-" + MONOCYPHER_COMMIT[:12])
        if not (cache / "src" / "monocypher.c").is_file():
            cache.mkdir(parents=True, exist_ok=True)
            print(f"  [*] Fetching Monocypher @ {MONOCYPHER_COMMIT[:12]} ...")
            run = lambda *a: subprocess.run(["git", "-C", str(cache)] + list(a),
                                            check=True, capture_output=True)
            run("init", "-q")
            run("fetch", "-q", "--depth", "1", MONOCYPHER_URL, MONOCYPHER_COMMIT)
            run("checkout", "-q", "FETCH_HEAD")
        head = subprocess.run(["git", "-C", str(cache), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True).stdout.strip()
        if head != MONOCYPHER_COMMIT:
            raise RuntimeError(f"Monocypher cache at {head[:12]}, pin is {MONOCYPHER_COMMIT[:12]}")
        return cache

    def _gen_monocypher(self):
        tree = self._monocypher_tree()
        raw = {}
        for rel, want in MONOCYPHER_FILES.items():
            data = (tree / rel).read_bytes()
            if want is not None and _sha256(data) != want:
                raise RuntimeError(f"{rel}: sha256 mismatch against the pin")
            raw[rel] = data.decode("utf-8")

        core_h  = raw["src/monocypher.h"]
        core_c  = _strip_local_includes(raw["src/monocypher.c"])
        ed_h    = _strip_local_includes(raw["src/optional/monocypher-ed25519.h"])
        ed_c    = _strip_local_includes(raw["src/optional/monocypher-ed25519.c"])
        licence = raw["LICENCE.md"]

        core_macros = _defined_macros(core_c)
        ed_macros   = _defined_macros(ed_c)

        out = [_provenance(
            "%s @ %s" % (MONOCYPHER_URL, MONOCYPHER_COMMIT),
            "%s (upstream commit date)" % MONOCYPHER_DATE,
            MONOCYPHER_PURPOSE,
            extra=[
                "Files:     " + ", ".join(
                    "%s %s" % (r, _sha256(raw[r].encode())[:16]) for r in MONOCYPHER_FILES),
                "",
                "Usage: include anywhere for the declarations. Exactly ONE translation",
                "unit per binary defines ETCS_MONOCYPHER_IMPLEMENTATION before the",
                "include to compile the bodies. Under C++ everything lives in",
                "namespace etcs_monocypher (Monocypher's MONOCYPHER_CPP_NAMESPACE).",
            ])]
        out.append("/*\n" + licence.replace("*/", "* /") + "*/\n")
        out.append("#ifndef ETCS_LIBS_MONOCYPHER_H__\n#define ETCS_LIBS_MONOCYPHER_H__\n")
        out.append("#if defined(__cplusplus) && !defined(MONOCYPHER_CPP_NAMESPACE)\n"
                   "#define MONOCYPHER_CPP_NAMESPACE etcs_monocypher\n#endif\n")
        out.append("\n// ===== monocypher.h =====\n" + core_h)
        out.append("\n// ===== optional/monocypher-ed25519.h =====\n" + ed_h)
        out.append("#endif // ETCS_LIBS_MONOCYPHER_H__\n")

        out.append("\n#if defined(ETCS_MONOCYPHER_IMPLEMENTATION) && "
                   "!defined(ETCS_MONOCYPHER_IMPLEMENTATION_DONE__)\n"
                   "#define ETCS_MONOCYPHER_IMPLEMENTATION_DONE__\n")
        out.append("\n// ===== monocypher.c =====\n" + core_c)
        # The two .c files were separate translation units upstream: their
        # private macros differ (FOR) and one static name repeats (hash_reduce).
        out.append("\n" + "".join("#undef %s\n" % m for m in core_macros))
        out.append("#define hash_reduce etcs_monocypher_ed25519_hash_reduce_\n")
        out.append("\n// ===== optional/monocypher-ed25519.c =====\n" + ed_c)
        out.append("\n#undef hash_reduce\n" + "".join("#undef %s\n" % m for m in ed_macros))
        out.append("#endif // ETCS_MONOCYPHER_IMPLEMENTATION\n")
        return "".join(out)
