"""ace abi subsystem.

Part of the `ace` dev tool, split by causal boundary: this file owns the
abi surface and nothing else. Mixed into AceManager in ace_install.py --
all methods are `self`-bound and may call across subsystems through the one
assembled object, but each subsystem's *definition* lives in exactly one file.
"""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import re

from .ace_common import (CYAN, YELLOW, GREEN, RED, PURPLE, ORANGE, RESET, DIM)


class AbiMixin:

    ABI_SUFFIX = "@@ETCS_ABI"
    _ABI_DISPATCH_KINDS = ("Work", "Stream")
    _ABI_TRIAD = ("Make", "MakeChild", "List", "GetHash")
    _ABI_LOADER_HOOKS = ("RegisterDynamicLoader", "RegisterRootSignalContext")
    _ABI_LIFECYCLE = ("Cleanup", "GetArena", "GetHash")
    _ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
    def _split_names_and_flags(self, args):
        """Partition `make module a b c -DFOO ASAN=1` into module names and
        build flags. A token is a FLAG iff it starts with '-' or contains '='
        (matching _validate_make_args' own -D / KEY=VALUE rule); everything
        else is a module name. Names go through _validate_module_name; only
        the flags go through _validate_make_args -- validating a bare module
        name as a make TARGET would wrongly reject it."""
        names, flags = [], []
        for a in args:
            if a.startswith("-") or "=" in a:
                flags.append(a)
            else:
                names.append(a)
        return names, flags

    def _strip_so_ext(self, name):
        """Drop a trailing .so / .dll / .dylib so `ace abi Foo.so` and
        `ace abi Foo` are the same request. Uses real suffix removal, NOT
        str.strip -- which strips a CHARACTER SET and would turn Physics.so
        into 'Physic' and Sos.so into 'S'."""
        for ext in (".so", ".dll", ".dylib"):
            if name.endswith(ext):
                return name[:-len(ext)]
        return name

    _FAMILIES_PER_ROW = 5

    def _family_rows(self, families, indent):
        """A tag's lineage as indented rows, _FAMILIES_PER_ROW to a row.

        Returns [] for a tag with no families, so the caller appends nothing
        rather than an empty line -- a flat tag should look flat."""
        if not families:
            return []
        fams = list(families)
        rows = []
        # Bracketed across the whole run, opening on the first row and closing
        # on the last, with continuations aligned under the opening bracket.
        # The tag's own methods sit at this same indent, so without the bracket
        # a wrapped lineage reads as two more method names -- the notation is
        # what says "this is one note about the tag", and it is the same
        # notation the single-line form used.
        for i in range(0, len(fams), self._FAMILIES_PER_ROW):
            chunk = fams[i:i + self._FAMILIES_PER_ROW]
            joined = " + ".join(f"{ORANGE}{f}{RESET}" for f in chunk)
            first = (i == 0)
            last = i + self._FAMILIES_PER_ROW >= len(fams)
            rows.append(f"{indent}{'[' if first else ' '}{joined}{']' if last else ' +'}")
        return rows

    def _print_name_grid(self, names, per_row=4, indent="    ", color=""):
        """Print names in a fixed-width grid, per_row across then wrap --
        four to a line makes a tidy square. Column width tracks the widest
        name so the columns stay aligned regardless of name length."""
        if not names:
            return
        width = max(len(n) for n in names) + 2
        for i in range(0, len(names), per_row):
            row = names[i:i + per_row]
            cells = "".join(f"{color}{n:<{width}}{RESET}" for n in row)
            print(f"{indent}{cells.rstrip()}")

    def _abi_store_dir(self):
        """Persisted tag-sets live beside the registry and the deps marker:
        they describe artifacts built on this machine, and must survive the
        tree being deleted and re-extracted."""
        d = self._get_registry_dir() / "abi"
        d.mkdir(exist_ok=True)
        return d

    def _bin_dir(self):
        return self.ace_root / "bin"

    def _read_dynamic_symbols(self, so_path):
        """Return the sorted list of exported ETCS ABI names in a shared
        object. Tries nm, then readelf; returns None if neither is available
        (a different condition from 'no symbols', and reported as such)."""
        so_path = Path(so_path)

        # nm -D --defined-only: T/t = text (exported code)
        if shutil.which("nm"):
            try:
                r = subprocess.run(
                    ["nm", "-D", "--defined-only", str(so_path)],
                    capture_output=True, text=True, timeout=30)
                if r.returncode == 0:
                    names = []
                    for line in r.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 3 and parts[1] in ("T", "t"):
                            sym = parts[2]
                            if sym.endswith(self.ABI_SUFFIX):
                                names.append(sym[:-len(self.ABI_SUFFIX)])
                    return sorted(set(names))
            except (subprocess.SubprocessError, OSError):
                pass

        # readelf --dyn-syms: FUNC + non-UND
        if shutil.which("readelf"):
            try:
                r = subprocess.run(
                    ["readelf", "-W", "--dyn-syms", str(so_path)],
                    capture_output=True, text=True, timeout=30)
                if r.returncode == 0:
                    names = []
                    for line in r.stdout.splitlines():
                        if " FUNC " not in line or " UND " in line:
                            continue
                        parts = line.split()
                        if not parts:
                            continue
                        sym = parts[-1]
                        if sym.endswith(self.ABI_SUFFIX):
                            names.append(sym[:-len(self.ABI_SUFFIX)])
                    return sorted(set(names))
            except (subprocess.SubprocessError, OSError):
                pass

        return None

    def _reconstruct_interface(self, so_path):
        """Reconstruct the tag-type interface of one .so from its exports.

        Returns a dict:
          {
            'module':    <str basename>,
            'loader':    [hook, ...],
            'lifecycle': [name, ...],
            'types': {
               <Tag>: {
                  'triad':   [present triad members],
                  'methods': { <Method>: {'dispatch': 'Work'|'Stream'|None,
                                          'hashed': bool} },
               }, ...
            },
            'unknown': [raw name, ...],   # anything the grammar didn't match
          }
        or None if the symbols could not be read.
        """
        names = self._read_dynamic_symbols(so_path)
        if names is None:
            return None

        module = Path(so_path).stem
        iface = {'module': module, 'loader': [], 'lifecycle': [],
                 'types': {}, 'unknown': []}

        def ensure(tag):
            return iface['types'].setdefault(tag, {'triad': [], 'methods': {}})

        for name in names:
            segs = name.split('_')

            if name in self._ABI_LOADER_HOOKS:
                iface['loader'].append(name)
                continue

            # module-scoped: prefix is the .so basename
            if segs[0] == module:
                if len(segs) == 1:
                    continue                      # the module symbol itself
                if len(segs) == 2 and segs[1] in self._ABI_LIFECYCLE:
                    iface['lifecycle'].append(name)
                    continue

            # tag method: <Tag>_<Method...>_<Kind>
            if len(segs) >= 3 and segs[-1] in ("Work", "Stream", "GetHash"):
                tag = segs[0]
                method = '_'.join(segs[1:-1])
                kind = segs[-1]
                slot = ensure(tag)['methods'].setdefault(
                    method, {'dispatch': None, 'hashed': False})
                if kind == 'GetHash':
                    slot['hashed'] = True
                else:
                    slot['dispatch'] = kind
                continue

            # tag-type triad member: <Tag>_{Make,List,GetHash}
            if len(segs) == 2 and segs[1] in self._ABI_TRIAD:
                ensure(segs[0])['triad'].append(segs[1])
                continue

            iface['unknown'].append(name)

        for t in iface['types'].values():
            t['triad'].sort()
        iface['loader'].sort()
        iface['lifecycle'].sort()
        iface['unknown'].sort()
        return iface

    def _interface_signature(self, iface):
        """Flatten an interface into a comparable dict of primitives -- what
        gets persisted and diffed. Deliberately excludes addresses (they move
        every build and mean nothing) and, for now, hash VALUES (unwired).
        Keeps hash PRESENCE, since a method losing its _GetHash pair is a real
        integrity regression worth flagging."""
        types = {}
        for tag, info in iface['types'].items():
            methods = {}
            for m, slot in info['methods'].items():
                methods[m] = {'dispatch': slot['dispatch'],
                              'hashed': slot['hashed']}
            types[tag] = {'triad': sorted(info['triad']), 'methods': methods}
        return {
            'module': iface['module'],
            'loader': sorted(iface['loader']),
            'lifecycle': sorted(iface['lifecycle']),
            'types': types,
            'unknown': sorted(iface['unknown']),
        }

    def _abi_record_path(self, module):
        return self._abi_store_dir() / f"{module}.json"

    def _load_abi_record(self, module):
        path = self._abi_record_path(module)
        if not path.exists():
            return None
        try:
            import json
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return None

    def _save_abi_record(self, module, signature):
        import json
        try:
            self._abi_record_path(module).write_text(
                json.dumps(signature, indent=2, sort_keys=True))
        except OSError as e:
            print(f"  [!] Could not persist ABI record for {module}: {e}")

    def _diff_interface(self, old, new):
        """Compare two signatures. Returns a list of human-readable change
        lines, most structural first. Empty list == identical."""
        if old is None:
            return []
        changes = []

        old_types = old.get('types', {})
        new_types = new.get('types', {})

        for tag in sorted(set(new_types) - set(old_types)):
            n = len(new_types[tag]['methods'])
            changes.append(f"+ tag-type {tag} ADDED ({n} method(s))")
        for tag in sorted(set(old_types) - set(new_types)):
            changes.append(f"- tag-type {tag} REMOVED")

        for tag in sorted(set(old_types) & set(new_types)):
            om = old_types[tag]['methods']
            nm = new_types[tag]['methods']

            for meth in sorted(set(nm) - set(om)):
                d = nm[meth]['dispatch'] or 'no-dispatch'
                changes.append(f"  {tag}: + method {meth} ({d})")
            for meth in sorted(set(om) - set(nm)):
                changes.append(f"  {tag}: - method {meth} removed")

            for meth in sorted(set(om) & set(nm)):
                od, nd = om[meth]['dispatch'], nm[meth]['dispatch']
                if od != nd:
                    changes.append(
                        f"  {tag}: ~ method {meth} dispatch {od} -> {nd}")
                if om[meth]['hashed'] and not nm[meth]['hashed']:
                    changes.append(
                        f"  {tag}: ! method {meth} LOST its _GetHash pair")
                elif not om[meth]['hashed'] and nm[meth]['hashed']:
                    changes.append(
                        f"  {tag}: + method {meth} gained a _GetHash pair")

            ot = set(old_types[tag]['triad'])
            nt = set(new_types[tag]['triad'])
            for miss in sorted(ot - nt):
                changes.append(f"  {tag}: ! triad member {miss} vanished")
            for got in sorted(nt - ot):
                changes.append(f"  {tag}: + triad member {got} appeared")

        if sorted(old.get('loader', [])) != sorted(new.get('loader', [])):
            changes.append(
                f"  loader hooks: {old.get('loader')} -> {new.get('loader')}")

        return changes

    def _visible_len(self, s):
        """Display width, ignoring ANSI colour codes -- len() counts the escape
        bytes and would misalign every coloured column."""
        return len(self._ANSI_RE.sub("", s))

    def _dispatch_token(self, slot):
        """Colour one method's dispatch kind, plus its hash-pair state."""
        d = slot['dispatch'] or f"{YELLOW}no-dispatch{RESET}"
        if slot['dispatch'] == 'Stream':
            d = f"{CYAN}Stream{RESET}"
        elif slot['dispatch'] == 'Work':
            d = f"{GREEN}Work{RESET}"
        return d + ("" if slot['hashed'] else f"  {YELLOW}(no hash){RESET}")

    def _interface_lines(self, iface, indent="  "):
        """Render one module's tag-set to a LIST OF LINES instead of printing.
        This is what lets several interfaces be spliced into side-by-side
        columns -- a printer can't be composited, a line list can.

        Each type is shown against its ONTOLOGY CONSTRAINT SURFACE when the
        module's sources can be read. The type's own work functions come first,
        being the most specific thing about it; everything else is grouped
        under the family it fulfils.

        ● and ○ mark SCRIPT REACH, not implementation. Every constraint method
        is implemented -- ETCS_DISPATCH_METHOD expands to a pure virtual, so a
        leaf that skipped one would not compile. ● means a work function of
        that exact name is exported, so a trace line can call it directly. ○
        means it is C++-only: reachable by any code holding the concrete type,
        and from a script by handing the RID to a work function that uses it.

        ○ is therefore not a defect, and often not even a gap. It is the normal
        shape for a method whose caller is the gate that owns the entity rather
        than the trace that wired it up -- NetworkProvider's parsers export none
        of Parser and are driven entirely through @rid arguments. The match is
        also by NAME, so a capability exported under a different word (a
        `Filter` work function against the `Accepts` constraint) reads as ○ too.
        What the column tells you is which calls a script can make, and nothing
        beyond that.
        """
        mod = iface['module']
        types = iface['types']
        lines = [f"{indent}{CYAN}{mod}{RESET} "
                 f"{DIM}({len(types)} tag-type(s)){RESET}"]
        if iface['loader']:
            lines.append(f"{indent}  {DIM}loader: "
                         f"{', '.join(iface['loader'])}{RESET}")

        try:
            tag_families = self._parse_module_leaves(mod)
        except Exception:
            tag_families = {}      # ontology overlay is additive; never fatal

        for tag in sorted(types):
            info = types[tag]
            triad = set(info['triad'])
            complete = triad >= set(self._ABI_TRIAD)
            mark = f"{GREEN}●{RESET}" if complete else f"{YELLOW}○{RESET}"
            missing = ""
            if not complete:
                missing = (f"  {YELLOW}[missing "
                           f"{', '.join(sorted(set(self._ABI_TRIAD) - triad))}]"
                           f"{RESET}")

            families = tag_families.get(tag)
            lines.append(f"{indent}  {mark} {PURPLE}{tag}{RESET}{missing}")
            # The lineage below the tag rather than beside it, five to a row.
            #
            # A cumulative lineage is long by design -- a camera leaf holds
            # nine families -- and on one line it set the width of the whole
            # report, so every other row was padded out by the widest thing
            # in the tree. Wrapping puts the cost where the length is: a
            # narrow tag stays one line, a wide one takes two, and nothing
            # else moves. A trailing "+" marks a row that continues, so the
            # break is visibly a wrap and not a second list.
            lines.extend(self._family_rows(families, f"{indent}      "))

            if not families:
                for meth in sorted(info['methods']):
                    lines.append(f"{indent}      {meth:<20} "
                                 f"{self._dispatch_token(info['methods'][meth])}")
                continue

            report = self._constraint_report(families, info['methods'].keys())

            for meth in report['own']:
                lines.append(f"{indent}      {meth:<20} "
                             f"{self._dispatch_token(info['methods'][meth])}")

            for family, rows in report['groups']:
                exported_n = sum(1 for _, ok in rows if ok)
                lines.append(f"{indent}    {ORANGE}{family} "
                             f"({exported_n}/{len(rows)}){RESET}")
                for meth, ok in rows:
                    if ok:
                        lines.append(f"{indent}      {GREEN}●{RESET} {meth:<18} "
                                     f"{self._dispatch_token(info['methods'][meth])}")
                    else:
                        lines.append(f"{indent}      {DIM}○ {meth}{RESET}")

            for meth, fams in report['collisions']:
                joined = f"{RED} + ".join(f"{ORANGE}{f}" for f in fams)
                lines.append(f"{indent}    {RED}! {meth} claimed by "
                             f"{joined}{RESET}")

        if iface['unknown']:
            lines.append(f"{indent}  {YELLOW}unrecognised exports: "
                         f"{', '.join(iface['unknown'])}{RESET}")
        return lines

    def _print_interface(self, iface, indent="  "):
        """Print one module's reconstructed tag-set (single column)."""
        for line in self._interface_lines(iface, indent):
            print(line)

    def _composite_columns(self, blocks, per_row=None, gap=3, buffer=1,
                           max_width=None, group_by_width=True):
        """Splice multi-line blocks into side-by-side columns, packing as many
        columns per band as the terminal width allows -- adaptive, not
        quantised. (C code powers-of-2 the column count because it can't
        cheaply know the terminal width; Python can, via get_terminal_size, so
        there's no reason to quantise -- we fit the real width directly.)

        Geometry is computed PREEMPTIVELY, the way you'd do it in C: pick the
        column count first, then the width of column-index k is the max width
        of every block that lands in column k across ALL bands, so column k has
        the same left edge in every band (globally aligned, not ragged per
        band). Each row then fills to those precomputed offsets + `buffer`.

        `per_row` caps the column count (None = no cap, purely width-driven).
        `gap` is the space between columns; `buffer` is slack added inside each
        column on top of its content width. No block is ever dropped -- a lone
        block wider than the terminal simply prints and may soft-wrap."""
        import shutil as _sh
        if not blocks:
            return []
        if max_width is None:
            max_width = _sh.get_terminal_size((100, 24)).columns

        block_w = [max((self._visible_len(l) for l in blk), default=0)
                   for blk in blocks]

        # Group blocks of similar width into the same band before laying out.
        #
        # Bands are filled sequentially, so declaration order puts whatever
        # happens to be adjacent next to each other -- one wide block in a band
        # of narrow ones stretches that band's tallest column and leaves the
        # rest of the row trailing whitespace to reach it, while the NEXT band
        # repeats the problem with a different offender. Sorting by width makes
        # each band internally uniform: the wide ones sit together, the narrow
        # ones sit together, and the ragged edge appears once (between bands)
        # instead of once per band.
        #
        # Stable, and descending, so ties keep declaration order and the widest
        # band leads -- which also means the column-index widths are settled by
        # the first band rather than drifting as later bands are measured.
        #
        # Purely presentational: this reorders how types are DISPLAYED, not any
        # ordering the ABI itself depends on (tag bit assignment, manifest
        # order, dispatch). If a caller ever needs the original sequence
        # preserved on screen, that wants a flag rather than removing this.
        if group_by_width and len(blocks) > 1:
            order = sorted(range(len(blocks)), key=lambda i: -block_w[i])
            blocks  = [blocks[i]  for i in order]
            block_w = [block_w[i] for i in order]

        def col_widths_for(cols):
            """Per-column-index max width across every band, for a given column
            count. Column k's width = widest block sitting at position k in any
            band."""
            widths = [0] * cols
            for idx, w in enumerate(block_w):
                k = idx % cols
                if w > widths[k]:
                    widths[k] = w
            return widths

        def total_for(cols):
            widths = col_widths_for(cols)
            # Must match the fill EXACTLY: each of `cols` cells is padded to
            # widths[k]+buffer, and cells are joined by (buffer+gap) spaces.
            return (sum(widths) + buffer * cols
                    + (buffer + gap) * (cols - 1))

        # Greedily pick the largest column count whose GLOBAL geometry fits the
        # terminal. Computed against the real per-column-index widths, not an
        # estimate, so what we plan is what prints.
        n = len(blocks)
        hi = n if per_row is None else min(per_row, n)
        cols = 1
        for c in range(hi, 0, -1):
            if c == 1 or total_for(c) <= max_width:
                cols = c
                break

        widths = col_widths_for(cols)
        pad_between = " " * (buffer + gap)
        out = []
        for start in range(0, n, cols):
            band = blocks[start:start + cols]
            height = max((len(blk) for blk in band), default=0)
            for row in range(height):
                cells = []
                for k, blk in enumerate(band):
                    cell = blk[row] if row < len(blk) else ""
                    pad = widths[k] + buffer - self._visible_len(cell)
                    cells.append(cell + " " * max(0, pad))
                out.append(pad_between.join(cells).rstrip())
            out.append("")
        return out

    def _module_so_path(self, module):
        """Where a built module's .so lands. Adjust if your layout differs."""
        return self._bin_dir() / f"{module}.so"

    def introspect_and_record(self, module, so_path=None, announce=True):
        """Reconstruct <module>'s interface, diff against the last persisted
        record, print any drift, then persist the new record.

        Called before a build so the drift shown is 'what you changed LAST
        time' -- the reminder pops regardless of what you're using ace for.
        Returns the new signature, or None if the .so could not be read.
        """
        if so_path is None:
            so_path = self._module_so_path(module)
        so_path = Path(so_path)

        if not so_path.exists():
            if announce:
                print(f"  {DIM}{module}: no built .so yet "
                      f"({so_path.name}) — ABI will be recorded after first build.{RESET}")
            return None

        iface = self._reconstruct_interface(so_path)
        if iface is None:
            print(f"  {YELLOW}{module}: could not read symbols "
                  f"(need nm or readelf).{RESET}")
            return None

        new_sig = self._interface_signature(iface)
        old_sig = self._load_abi_record(module)
        changes = self._diff_interface(old_sig, new_sig)

        if announce:
            self._print_interface(iface)
            if changes:
                print(f"\n  {YELLOW}▲ ABI changed since the last build "
                      f"of {module}:{RESET}")
                for line in changes:
                    print(f"    {line}")
                print()
            elif old_sig is not None:
                print(f"  {GREEN}ABI unchanged since last build.{RESET}")

        self._save_abi_record(module, new_sig)
        return new_sig

    def _registered_modules(self):
        """Modules known to the tree via the modules/ directory, independent
        of whether they are built. Returns (native, external) lists of Paths.
        Native = a real in-tree dir with a Makefile; external = a symlink."""
        modules_dir = self.ace_root / "modules"
        if not modules_dir.exists():
            return [], []
        external = sorted([m for m in modules_dir.iterdir() if m.is_symlink()])
        native = sorted([
            m for m in modules_dir.iterdir()
            if not m.is_symlink() and m.is_dir() and (m / "Makefile").exists()
        ])
        return native, external

    def _render_and_record(self, module, so_path):
        """Reconstruct one module, persist its record, and return
        (lines, drift) -- lines is the columnable interface block, drift is the
        list of change strings (printed separately, since variable-height drift
        banners don't belong inside fixed-width columns)."""
        iface = self._reconstruct_interface(so_path)
        if iface is None:
            return ([f"  {YELLOW}{module}: unreadable{RESET}"], [])
        new_sig = self._interface_signature(iface)
        old_sig = self._load_abi_record(module)
        drift = self._diff_interface(old_sig, new_sig)
        self._save_abi_record(module, new_sig)
        return (self._interface_lines(iface), drift)

    def _print_interfaces_columned(self, built, per_row=None):
        """Composite every built module's interface into side-by-side columns,
        then print any drift banners underneath. `built` is [(name, path)]."""
        blocks, drifts = [], []
        for module, so in built:
            lines, drift = self._render_and_record(module, so)
            blocks.append(lines)
            if drift:
                drifts.append((module, drift))
        for line in self._composite_columns(blocks, per_row=per_row):
            print(line)
        for module, drift in drifts:
            print(f"  {YELLOW}▲ ABI changed since last build of "
                  f"{module}:{RESET}")
            for c in drift:
                print(f"    {c}")
            print()

    def _all_module_sos(self):
        """Every built module .so in bin/, as (module_name, path)."""
        bin_dir = self._bin_dir()
        if not bin_dir.exists():
            return []
        out = []
        for so in sorted(bin_dir.glob("*.so")):
            out.append((so.stem, so))
        return out

    def abi(self, args):
        """`ace abi [module]` -- print the current tag-set without building.

        No arg: every module in bin/. With arg: that one module, with or
        without a .so/.dll/.dylib suffix. Same reconstruction the build path
        runs, exposed on its own so you can interrogate the interface any time."""
        if args:
            module = self._validate_module_name(self._strip_so_ext(args[0]))
            self.introspect_and_record(module, announce=True)
            return

        self._list_all_modules()

    def _list_all_modules(self):
        """The unified module view: everything the tree knows about, whether
        built or not. This is what bare `ace abi` (and the `ace list` alias)
        show. It fuses two sources that don't fully overlap --

            bin/*.so         modules that are BUILT (introspectable ABI)
            modules/         modules that are REGISTERED (native or external)

        -- because a module can be registered but unbuilt (no .so yet), or a
        stale .so can outlive its registry entry. Reporting only one source
        would hide real state, so both are shown and cross-referenced."""
        built = self._all_module_sos()                       # [(name, path)]
        built_names = {name for name, _ in built}
        native, external = self._registered_modules()
        native_names = {p.name for p in native}
        external_names = {p.name for p in external}
        registered = native_names | external_names
        all_names = built_names | registered

        if not all_names:
            print(f"  {DIM}No modules registered or built.{RESET}")
            return

        print("""\nWork Functions Reminder (○/●): 
All types implement the full *Concrete() interface, whether they expose it to ETCS scripts or not.
The (○/●) token indicates what is namable from an external frame of reference (from an ETCS script, not another C++ work func).
The (●) work functions are an explicit labeling of what is callable from an external frame of reference, whereas
The (○) work functions can only be called within C++ in other work functions with references to a type of that base, ex:\n
requires something [Window]\n
That something can have any (●) work function called on it for the Window base with certainty that the result will deterministically pass/fail,
based off of the exposed work function interface. You can specify a more exact type like:\n
requires win [Window, WindowProvider::GLFWWindow]\n
Now win is exactly the concrete type for GLFW or the script refuses to run, that invariant is upheld for the rest of the script.\n
Within a work function:\n

DEFINE_WORK_FUNC(SomeType, SomeAction)
{
    (void)ctx;
    data.writeString((self.SomeOtherUnexposedAction().toString() + "\\n" + self.SomeAction(data.restAsString()).toString()).c_str());
}

Where:
  SomeType
    ○ SomeOtherUnexposedAction
    ● SomeAction

ETCS scripts can only call SomeAction.
          """)

        print(f"\n--- ACE Modules ({len(all_names)}) ---\n")

        # Registry overview first: native vs external, gridded 4-across.
        if native:
            print(f"  {DIM}native (in-tree):{RESET}")
            self._print_name_grid(sorted(native_names), per_row=4,
                                  indent="    ", color=YELLOW)
        if external:
            print(f"  {DIM}external (symlinked):{RESET}")
            self._print_name_grid(sorted(external_names), per_row=4,
                                  indent="    ", color=CYAN)
            for item in external:
                print(f"      {DIM}{item.name} -> {item.resolve()}{RESET}")

        # Registered but NOT built -- the state a bin/-only view would hide.
        unbuilt = sorted(registered - built_names)
        if unbuilt:
            print(f"\n  {YELLOW}registered but not built "
                  f"({len(unbuilt)}):{RESET}")
            self._print_name_grid(unbuilt, per_row=4, indent="    ",
                                  color=YELLOW)

        # Built but NOT registered -- a stale .so whose module is gone.
        orphan = sorted(built_names - registered)
        if orphan:
            print(f"\n  {RED}built but not registered "
                  f"({len(orphan)}) — stale .so?:{RESET}")
            self._print_name_grid(orphan, per_row=4, indent="    ", color=RED)

        print(f"\n  {DIM}global registry: {self._get_registry_dir()}{RESET}")

        # Then the actual ABI interfaces for everything built -- composited
        # four-across into columns, not stacked sequentially.
        if built:
            print(f"\n--- ETCS Tag-Set ({len(built)} built) ---\n")
            self._print_interfaces_columned(built)

    def _announce_full_tagset(self, heading="ETCS Tag-Set before build"):
        """Print the whole tag-set across every built module, recording drift
        per module. A 4-across name grid heads the section as an overview,
        then each module's full interface follows. Used before/after
        `ace make modules`."""
        built = self._all_module_sos()
        if not built:
            return
        print(f"\n--- {heading} ({len(built)} module(s)) ---\n")
        self._print_name_grid([mod for mod, _so in built],
                              per_row=4, indent="  ", color=CYAN)
        print()
        self._print_interfaces_columned(built)
