"""ace_wasm -- what a wasm link did NOT tell you.

WHY THIS SUBSYSTEM EXISTS. A -sMAIN_MODULE build has to link with
-sERROR_ON_UNDEFINED_SYMBOLS=0, because a side module legitimately imports what
it will find at runtime. The cost is that a symbol NOBODY defines stops being a
link error: emscripten hands the side module a lazy stub

    stubs[prop] = (...args) => { resolved ||= resolveSymbol(prop);
                                 return resolved(...args) }

and the program dies the first time that import is actually CALLED, as

    TypeError: resolved is not a function

with a stack that names neither the symbol nor the module -- typically pointing
inside dlopen, so it reads like a toolchain bug. Worse, a stub that is never
called never throws, so the same pair of binaries looks fine until a code path
reaches it. A whole family of missing names almost always means the MAIN link is
missing the -s flag that pulls in that JS library, which is precisely the kind of
mistake a build tool should catch rather than a browser.

`ace wasm link` does the set difference the linker declined to do, and runs
automatically at the end of every web loader build (ace_build) because the main
link is the only place those flags can go.

`ace wasm addr` is the other half: a browser reports a wasm fault as
`etcs.wasm:wasm-function[197]:0x906b4`, and with -O2 there is no name section to
turn that into anything. This reads the export table and answers with the
symbol, which is the difference between a stack trace and a guess.

Both read the binaries directly -- no emsdk, no wabt -- so they work on a
downloaded artifact and cannot disagree with the toolchain about what is in the
file.
"""
import os
import shutil
import subprocess
from pathlib import Path

from .ace_common import CYAN, YELLOW, GREEN, RED, RESET, DIM


# ── wasm binary reading ──────────────────────────────────────────────────────
#
# Only the four sections these questions need: imports (2), exports (7), code
# (10) and the optional name section (custom, id 0, named "name"). Deliberately
# not a general parser -- a partial reader that is obviously correct about the
# fields it reads beats a full one that is hard to check.

def _uleb(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7f) << s
        if not (x & 0x80):
            return r, i
        s += 7


def _name(b, i):
    n, i = _uleb(b, i)
    return b[i:i + n].decode('utf-8', 'replace'), i + n


def _sections(b):
    """(section_id, payload_start, payload_end) for each section, in order."""
    if b[:4] != b'\0asm':
        raise ValueError('not a wasm binary (bad magic)')
    i = 8
    while i < len(b):
        sid = b[i]; i += 1
        size, i = _uleb(b, i)
        yield sid, i, i + size
        i += size


def _imports(b):
    """env/GOT imports, bucketed by kind.

    GOT.func and GOT.mem are ADDRESS relocations rather than calls, so a missing
    one fails differently from "resolved is not a function" -- they are bucketed
    separately rather than dropped so that --got can ask about them at all.
    """
    out = {'func': set(), 'global': set(), 'other': set(),
           'got_func': set(), 'got_mem': set(), 'n_func': 0}
    for sid, s, e in _sections(b):
        if sid != 2:
            continue
        count, i = _uleb(b, s)
        for _ in range(count):
            mod, i = _name(b, i)
            fld, i = _name(b, i)
            kind = b[i]; i += 1
            if kind == 0:                        # func: typeidx
                _, i = _uleb(b, i)
                bucket = 'func'
                out['n_func'] += 1
            elif kind == 1:                      # table: reftype + limits
                i += 1
                flags = b[i]; i += 1
                _, i = _uleb(b, i)
                if flags & 1:
                    _, i = _uleb(b, i)
                bucket = 'other'
            elif kind == 2:                      # memory: limits
                flags = b[i]; i += 1
                _, i = _uleb(b, i)
                if flags & 1:
                    _, i = _uleb(b, i)
                bucket = 'other'
            elif kind == 3:                      # global: valtype + mutability
                i += 2
                bucket = 'global'
            elif kind == 4:                      # tag: attribute + typeidx
                i += 1                           # -fwasm-exceptions makes every
                _, i = _uleb(b, i)               # module import env.__cpp_exception
                bucket = 'other'
            else:
                raise ValueError('unknown import kind %d' % kind)
            if mod == 'GOT.func':
                out['got_func'].add(fld); continue
            if mod.startswith('GOT.'):
                out['got_mem'].add(fld); continue
            out[bucket].add(fld)
    return out


def _exports(b):
    """{name} of everything exported, and {funcidx: [names]} for functions."""
    names, by_idx = set(), {}
    for sid, s, e in _sections(b):
        if sid != 7:
            continue
        count, i = _uleb(b, s)
        for _ in range(count):
            fld, i = _name(b, i)
            kind = b[i]; i += 1
            idx, i = _uleb(b, i)
            names.add(fld)
            if kind == 0:
                by_idx.setdefault(idx, []).append(fld)
    return names, by_idx


def _imported_func_count(b):
    return _imports(b)['n_func']


def _code_bodies(b):
    """(function_index, body_start, body_end) for each defined function.

    The index is the GLOBAL one -- imported functions occupy the low indices, so
    a browser's `wasm-function[N]` only matches once they are counted.
    """
    base = _imported_func_count(b)
    for sid, s, e in _sections(b):
        if sid != 10:
            continue
        count, i = _uleb(b, s)
        for n in range(count):
            size, i = _uleb(b, i)
            yield base + n, i, i + size
            i += size


def _name_section(b):
    """{funcidx: name} from the custom "name" section, empty when stripped."""
    out = {}
    for sid, s, e in _sections(b):
        if sid != 0:
            continue
        nm, i = _name(b, s)
        if nm != 'name':
            continue
        while i < e:
            sub = b[i]; i += 1
            sz, i = _uleb(b, i)
            end = i + sz
            if sub == 1:                         # function names
                count, j = _uleb(b, i)
                for _ in range(count):
                    idx, j = _uleb(b, j)
                    fn, j = _name(b, j)
                    out[idx] = fn
            i = end
    return out


def _demangle(sym):
    """Itanium name, made readable when c++filt is available; unchanged if not."""
    if not sym.startswith('_Z'):
        return sym
    exe = shutil.which('c++filt') or shutil.which('llvm-cxxfilt')
    if not exe:
        return sym
    try:
        out = subprocess.run([exe, sym], capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or sym
    except Exception:
        return sym


def _glue_text(path):
    """The JS glue as one string, or None.

    NOT a parse of wasmImports. The glue is minified onto one line and its
    import table is assembled from several places, so anything structural would
    be guesswork. A substring test is the honest form of the question actually
    being asked -- "is this name anywhere in the JavaScript?" -- and it can only
    produce false NEGATIVES, which is the right way round: a clean run is weaker
    evidence than a dirty one.
    """
    try:
        with open(path, 'r', errors='replace') as f:
            return f.read()
    except OSError:
        return None


class WasmMixin:
    """`ace wasm { link | addr }`."""

    # ── entry point ──────────────────────────────────────────────────────────

    def wasm(self, args):
        if not args:
            print("    Usage: ace wasm { make { all | modules | loaders | module <n> "
                  "| loader <n> } }")
            print("                    { link [main.wasm side.wasm ...] [--got] }")
            print("                    { addr <file.wasm> <offset> }")
            return 0
        sub, rest = args[0], args[1:]
        if sub == "make":
            return self.wasm_make(rest)
        if sub == "link":
            return self.wasm_link(rest)
        if sub == "addr":
            return self.wasm_addr(rest)
        print(f"{RED}[-] Unknown wasm subcommand: '{sub}'{RESET}")
        return 1

    # ── the web build ────────────────────────────────────────────────────────

    def _web_modules(self):
        """Modules whose manifest declares the Web platform, in manifest order.

        The list has to come from the manifests rather than from the tree,
        because "builds for the web" is a claim a module makes and not something
        a directory listing can answer -- and a module that has not made it fails
        its generated Makefile's own $(error) rather than producing a .wasm
        nobody can load.
        """
        out = []
        for name in self._all_manifests():
            try:
                m = self.load_manifest(name, silent=True)
            except Exception:
                continue
            plats = m.get("module", {}).get("platforms", ["Linux"])
            if "Web" in plats:
                out.append(name)
        return out

    def _web_unclaimed(self):
        """Modules in the tree that this cannot speak for either way.

        A module with no manifest of its own builds from default.json, and
        default.json declares every platform -- so "declares Web" says nothing
        about it, and a set built from that would sweep in every module in the
        tree whether or not it has ever been compiled for the web. They are
        LISTED rather than guessed at: a module that does build for the web and
        is missing here wants a manifest, and one that does not wants to stay
        out, and only its author knows which.
        """
        return [m for m in self._defaulted_modules() if m not in self._web_modules()]

    def wasm_make(self, args):
        """`ace make ... EMSCRIPTEN=1`, over the set that declares Web.

        Exists because the plain targets cannot be reused as they are: `ace make
        modules` walks every module in the tree, and most of them declare no Web
        platform, so a web build of "all of them" is a wall of errors about
        modules that were never meant to cross. This selects instead of failing.

        Ordinary flags still pass through, so `ace wasm make loaders
        -DETCS_REPL_SHELL` behaves exactly as the native spelling does.
        """
        if not args:
            print("    Usage: ace wasm make { all | modules | loaders | module <n> "
                  "| loader <n> } [FLAGS...]")
            return 0

        target, rest = args[0], args[1:]
        extras = list(rest) + ["EMSCRIPTEN=1"]

        if target in ("module", "loader"):
            if not rest:
                print(f"{RED}[-] ace wasm make {target} needs a name.{RESET}")
                return 1
            name, tail = rest[0], rest[1:]
            self.make([target, name] + list(tail) + ["EMSCRIPTEN=1"])
            return 0

        if target == "loaders":
            self.make(["loaders"] + extras)
            return 0

        if target in ("modules", "all"):
            mods = self._web_modules()
            if not mods:
                print(f"{YELLOW}[!] No manifest declares the Web platform. Add 'Web' "
                      f"to module.platforms.{RESET}")
                return 1
            print(f"\n--- Web build: {len(mods)} module(s) declaring Web ---")
            print(f"  {DIM}{', '.join(mods)}{RESET}")
            unclaimed = self._web_unclaimed()
            if unclaimed:
                print(f"  {YELLOW}not built{RESET} {DIM}(no manifest of their own, so "
                      f"nothing declares them either way):{RESET}")
                print(f"    {DIM}{', '.join(unclaimed)}{RESET}")
                print(f"    {DIM}ace wasm make module <n> builds one anyway; a manifest "
                      f"with \"Web\" in module.platforms puts it in this set.{RESET}")
            print()
            failed = []
            for name in mods:
                try:
                    self.make(["module", name] + list(rest) + ["EMSCRIPTEN=1"])
                except Exception as ex:
                    failed.append((name, ex))
            if target == "all":
                self.make(["loaders"] + extras)
            if failed:
                for name, ex in failed:
                    print(f"  {RED}[-] {name}: {ex}{RESET}")
                return 1
            return 0

        print(f"{RED}[-] Unknown wasm make target: '{target}'{RESET}")
        return 1

    # ── link check ───────────────────────────────────────────────────────────

    def _web_artifacts(self):
        """(main, [sides], glue) from bin/, which is where copy_loaders puts them."""
        bin_dir = self.ace_root / "bin"
        main = bin_dir / "etcs.wasm"
        glue = bin_dir / "etcs.js"
        sides = sorted(p for p in bin_dir.glob("*.wasm") if p != main)
        return main, sides, (glue if glue.exists() else None)

    def wasm_link(self, args, quiet_when_clean=False):
        """Name every symbol a side module imports that nothing provides.

        Returns 0 when everything resolves, 1 otherwise, so it works as a gate.
        With no arguments it checks the current tree's web build.
        """
        want_got = "--got" in args
        paths = [Path(a) for a in args if not a.startswith("--")]
        glue = None
        if paths:
            main, sides = paths[0], paths[1:]
            cand = main.with_suffix(".js")
            glue = cand if cand.is_file() else None
        else:
            main, sides, glue = self._web_artifacts()

        if not main.exists():
            print(f"{YELLOW}[!] No web build to check ({main} absent). "
                  f"Build one with: ace make loader etcs EMSCRIPTEN=1{RESET}")
            return 0
        if not sides:
            print(f"{YELLOW}[!] {main.name} has no side modules next to it -- "
                  f"nothing to check against.{RESET}")
            return 0

        blob = main.read_bytes()
        provided, _ = _exports(blob)
        own = len(provided)
        side_blobs = {p: p.read_bytes() for p in sides}
        for b in side_blobs.values():
            provided |= _exports(b)[0]          # a side module can satisfy a sibling
        glue_txt = _glue_text(glue) if glue else None

        lines = []
        lines.append(f"\n--- ETCS Wasm Link Check ---")
        lines.append(f"  main   {main.name}  {DIM}{own} exports "
                     f"(+ side modules -> {len(provided)} provided){RESET}")
        if glue_txt is not None:
            lines.append(f"  glue   {glue.name}")

        bad = 0
        for p, b in side_blobs.items():
            imp = _imports(b)
            # __memory_base/__table_base are answered by the dylink proxy's own
            # switch, never by a lookup -- see proxyHandler.get in the glue.
            missing_f = sorted(n for n in imp['func'] if n not in provided)
            missing_g = sorted(n for n in imp['global'] if n not in provided
                               and n not in ('__memory_base', '__table_base'))
            hard_f = [n for n in missing_f
                      if glue_txt is None or n not in glue_txt]
            js_f = [n for n in missing_f if n not in hard_f]
            hard_g = [n for n in missing_g
                      if glue_txt is None or n not in glue_txt]
            if not hard_f and not hard_g:
                extra = f" {DIM}({len(js_f)} via the JS glue){RESET}" if js_f else ""
                lines.append(f"  {GREEN}OK{RESET}     {p.name}{extra}")
                continue
            bad = 1
            lines.append(f"  {RED}MISSING{RESET} {p.name}  "
                         f"{len(hard_f)} function(s), {len(hard_g)} global(s)")
            for n in hard_f:
                lines.append(f"           {RED}{n}{RESET}")
            for n in hard_g:
                lines.append(f"           {YELLOW}{n}{RESET} {DIM}(global){RESET}")

        if want_got:
            lines.extend(self._got_report(side_blobs, provided, glue_txt))

        if bad:
            lines.append("")
            lines.append(f"  {RED}Each name above is in NEITHER the main module nor the "
                         f"glue.{RESET}")
            lines.append("  It becomes a lazy stub that throws \"resolved is not a "
                         "function\" the")
            lines.append("  first time it is CALLED -- silent until a code path reaches "
                         "it. A whole")
            lines.append("  family of them means the MAIN link is missing the -s flag "
                         "for that JS")
            lines.append("  library (a module's Web profile declares it; the loader link "
                         "carries it).")
        elif not quiet_when_clean:
            lines.append(f"\n  {GREEN}Every side-module import resolves.{RESET}")

        if bad or not quiet_when_clean:
            print("\n".join(lines))
        return bad

    def _got_report(self, side_blobs, provided, glue_txt):
        """GOT.func entries that resolve to a JS-library function.

        A different and worse failure than a missing call. updateGOT fills a
        GOT.func entry with

            if (typeof value == "function") newValue = addFunction(value)

        -- ONE argument, so addFunction's own `sig` is undefined. Harmless while
        the value is a wasm export, because setWasmTableEntry takes one directly.
        For a plain JS function setWasmTableEntry throws, addFunction falls back
        to convertJsFunctionToWasm(func, sig), and sig.slice(1) is

            TypeError: can't access property "slice", sig is undefined

        so such a name is a live crash the moment a thread relocates it -- and
        the stack names neither the symbol nor the module.
        """
        out = [f"\n  {DIM}GOT.func entries resolving to a JS-library function:{RESET}"]
        found = False
        for p, b in side_blobs.items():
            got = _imports(b)['got_func']
            hits = [n for n in sorted(got)
                    if n not in provided and glue_txt is not None and n in glue_txt]
            out.append(f"    {p.name}: {len(got)} GOT.func, {len(hits)} JS-library")
            for n in hits:
                found = True
                out.append(f"      {YELLOW}{n}{RESET}")
        if not found:
            out.append(f"    {DIM}(none -- every other GOT.func entry is a wasm export "
                       f"or genuinely absent){RESET}")
        return out

    # ── offset -> symbol ─────────────────────────────────────────────────────

    def wasm_addr(self, args):
        """Map a browser's `wasm-function[N]:0xOFFSET` to a symbol.

        Takes the OFFSET (the part after the colon), which is a byte position in
        the file, and answers with the function whose body contains it. The name
        comes from the name section when the build kept one, and otherwise from
        the export table -- which -sEXPORT_ALL makes almost complete, and is why
        this works on an ordinary -O2 artifact.
        """
        if len(args) < 2:
            print("    Usage: ace wasm addr <file.wasm> <offset>   "
                  f"{DIM}(offset as printed by the browser, e.g. 0x906b4){RESET}")
            return 1
        path = Path(args[0])
        if not path.exists():
            print(f"{RED}[-] No such file: {path}{RESET}")
            return 1
        try:
            off = int(args[1], 0)
        except ValueError:
            print(f"{RED}[-] Not an offset: {args[1]}{RESET}")
            return 1

        blob = path.read_bytes()
        _, by_idx = _exports(blob)
        names = _name_section(blob)

        for idx, start, end in _code_bodies(blob):
            if not (start <= off < end):
                continue
            sym = names.get(idx) or (by_idx.get(idx) or [None])[0]
            print(f"\n  {CYAN}{path.name}{RESET} {hex(off)} "
                  f"-> function #{idx}")
            print(f"    body {hex(start)}..{hex(end)}  "
                  f"{DIM}({end - start} bytes, {off - start} bytes in){RESET}")
            if sym:
                print(f"    {GREEN}{sym}{RESET}")
                pretty = _demangle(sym)
                if pretty != sym:
                    print(f"    {DIM}{pretty}{RESET}")
            else:
                print(f"    {YELLOW}no name{RESET} {DIM}-- not exported and the name "
                      f"section is stripped. Relink with --profiling-funcs to keep "
                      f"names.{RESET}")
            return 0

        print(f"{YELLOW}[!] {hex(off)} is not inside any function body in "
              f"{path.name}.{RESET}")
        return 1
