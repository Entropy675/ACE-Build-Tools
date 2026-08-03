#!/usr/bin/env python3
"""
ETCS Script Viewer - Interactive TUI

Features:
- File browser mode when called without arguments
- Hybrid navigation: jumps between .etcs refs, but free-scrolls at the ends
- Shebang line is initially highlighted (represents root script)
- Enter to open in editor (respects $EDITOR/$VISUAL, defaults to nano)
- Auto-reload expanded content after editing
- Page Up/Down, Home/End for faster navigation
- Left arrow/Backspace to back out of scripts or folders
- Opening a file carrying the '#EXPORT' marker defaults to the interactive 
  export STACK builder. Opening a file without it defaults to the inline 
  .etcs viewer.
- Tab toggles between the Stack Builder and the inline .etcs viewer, BUT 
  ONLY if the file has the '#EXPORT' marker. Files without it cannot access 
  the Stack view. Unsaved stack state survives the toggle.
- 'e' or Tab in browser mode opens the interactive export.etcs stack builder
  from the current stack state (resumes if you already started building).
- q or Escape to quit

Annotation convention for casual name declarations: NONE. Sockets are
found by actually reading the file's context/tag-declare lines
(scan_sockets) -- specifically the ones the real engine treats as an
UNRESOLVED pending-name binding, not by a special comment format.
Explicit 'spawn <name>' and 'as <name>' lines are deliberately NOT
treated as sockets: both unconditionally overwrite any existing binding
for that name at runtime (CmdSpawn's overwrite=true, CmdBind's unchecked
ctx.bind()), so an external run/detach binding injected under either
name would just get clobbered the moment the line executes -- exposing
them as bindable in the export builder would be misleading. See
scan_sockets' docstring for exactly what it does and does not handle
correctly.

Second-line file directives: '#EXPORT' and '#IMPORT <path>' are mutually
exclusive by construction, not by any validation this tool performs --
both are defined to occupy the exact same second line (right after the
shebang), so a single line of text can only ever be one or the other, or
neither. '#IMPORT <path>' declares the one folder (beyond the local
directory) this file's own run/detach references may additionally
resolve against, matching the real engine's script-path resolution. See
get_import_target's and resolve_script_path's docstrings for the exact
single-hop semantics.
"""

import sys
import os
import re
import subprocess
import hashlib
from pathlib import Path
import curses

# --- Session ---------------------------------------------------------------
# The supervisor lives in the ace manager. `ace` is already the process that
# owns the tree, the registry and every subprocess this system spawns, so the
# thing that owns the terminal belongs with it rather than beside this file.
# Found by tree layout first (this file sits at <ace_root>/scripts/), then via
# `ace root`, so the editor still works when ace is not on PATH.
_ace_module = None
_ace_module_tried = False


def get_ace_module():
    """Import ace_install.py for its session API. None if unavailable."""
    global _ace_module, _ace_module_tried
    if _ace_module_tried:
        return _ace_module
    _ace_module_tried = True
    import importlib.util
    candidates = [Path(__file__).resolve().parent.parent / "ace_install.py"]
    root = get_ace_root()
    if root:
        candidates.append(Path(root) / "ace_install.py")
    for cand in candidates:
        try:
            if not cand.exists():
                continue
            spec = importlib.util.spec_from_file_location("ace_install", cand)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "AceSession"):
                _ace_module = mod
                break
        except Exception:
            continue
    return _ace_module

ETCS_REF_PATTERN = re.compile(
    r'(run|detach)\s+(\S+\.etcs)',
    re.IGNORECASE
)

SELECTABLE_KINDS = ('layer_header', 'socket', 'available')

EXPORT_MARKER = "#EXPORT"
IMPORT_MARKER_PREFIX = "#IMPORT"
SWITCH_TO_VIEWER = "SWITCH_TO_VIEWER"

_CONTEXT_LINE_RE = re.compile(r'^context\s+(\S+)::(\S+)\s+(\S+)\s*$')
_RUN_DETACH_LINE_RE = re.compile(r'^(run|detach)\s+(\S+\.etcs)(.*)$', re.IGNORECASE)

# --- Session state for mode-switching ---
# Keyed by resolved dirpath (for browser 'e' key) or resolved filepath 
# (for toggling views on a specific export file).
_builder_sessions = {}

# --- Live runtime ----------------------------------------------------------
# The editor and the runtime are peers, not parent and child: both are held by
# one Session that owns the terminal, and a swap is only a question of which
# one is currently attached to it. That is what lets the runtime keep its REPL
# state across edits -- re-running feeds the newly composed script into the
# process that is already up rather than restarting it.
TEMP_RUN_SUFFIX = "_temporary_edit"
ETCS_RUNTIME_ARGV = None        # None -> [<ace root>/bin/etcs] or ['etcs']

_runtime_session = None


def get_session():
    """This process's own AceSession, created on first relevance. Only used
    when the editor is NOT running under `ace session` -- in that case it
    hosts the handover itself."""
    global _runtime_session
    mod = get_ace_module()
    if _runtime_session is None and mod is not None:
        _runtime_session = mod.AceSession()
    return _runtime_session


def _runtime_argv():
    if ETCS_RUNTIME_ARGV:
        return list(ETCS_RUNTIME_ARGV)
    return [get_ace_shebang() or "etcs"]


def run_script_now(stdscr, script_path, cwd=None):
    """Run a script, preferring an already-live runtime over starting one.

    Three tiers, in order of how much state they preserve:

      1. An `ace session` is running -- feed the script to the runtime it is
         already supervising. Never starts a second one; that is the whole
         point of the socket.
      2. No session, but the ace module is importable -- host the handover in
         this process. Ctrl+] comes back here, runtime keeps its REPL state.
      3. Neither -- one-shot foreground run. The export carries its own
         shebang and is chmod 755, so it can execute directly.
    """
    script_path = Path(script_path)
    cwd = str(cwd) if cwd else str(script_path.parent)
    mod = get_ace_module()

    if mod is not None:
        reply = mod.session_request(f"RUN {script_path.resolve()}")
        if reply and reply.startswith("OK"):
            return "sent to the ace session's runtime — swap to that terminal"
        if reply:
            return f"session refused it: {reply}"

    if mod is not None:
        swap = getattr(mod, "SWAP_KEY", 0x1D)
        banner = (f"\r\n\033[36m[etcs]\033[0m {script_path.name} — "
                  f"Ctrl+{chr(swap + 64)} returns to the editor, "
                  f"runtime keeps running\r\n")
        outcome = mod.run_from_curses(
            stdscr, get_session(), 'runtime', _runtime_argv(), cwd=cwd,
            feed=mod.ETCS_RUN_COMMAND.format(path=script_path), banner=banner)
        return {'swap': "detached from the runtime — r reattaches",
                'exit': "runtime exited",
                'absent': "could not start the runtime"}.get(outcome, "")

    curses.def_prog_mode()
    curses.endwin()
    try:
        try:
            subprocess.run([str(script_path)], cwd=cwd)
        except (OSError, subprocess.SubprocessError) as e:
            print(f"\n Could not run {script_path}: {e}")
        input("\n [enter] to return to the editor ")
    finally:
        curses.reset_prog_mode()
        stdscr.touchwin()
        stdscr.refresh()
    return "runtime exited"


def run_stack_now(stdscr, dirpath, stack, name):
    """Write the stack to a scratch export and run it."""
    export_path, conflicts = _write_export(dirpath, stack, name)
    status = run_script_now(stdscr, export_path, cwd=dirpath)
    if conflicts:
        status = f"{len(conflicts)} name/type conflict(s) — see save output"
    return status


class LineInfo:
    """Holds metadata about each expanded line."""
    __slots__ = ['text', 'indent_level', 'source_path', 'is_ref',
                 'ref_path', 'ref_name', 'is_shebang', 'is_open_brace', 'is_close_brace']

    def __init__(self, text, indent_level, source_path=None,
                 is_ref=False, ref_path=None, ref_name=None,
                 is_shebang=False, is_open_brace=False, is_close_brace=False):
        self.text = text
        self.indent_level = indent_level
        self.source_path = source_path
        self.is_ref = is_ref
        self.ref_path = ref_path
        self.ref_name = ref_name
        self.is_shebang = is_shebang
        self.is_open_brace = is_open_brace
        self.is_close_brace = is_close_brace


class FileEntry:
    """Holds info about a file/directory in browser mode."""
    __slots__ = ['name', 'path', 'is_dir', 'is_etcs']

    def __init__(self, name, path, is_dir, is_etcs):
        self.name = name
        self.path = path
        self.is_dir = is_dir
        self.is_etcs = is_etcs


class StackLayer:
    """One script pushed onto the export builder's stack."""
    __slots__ = ['file', 'mode', 'sockets', 'bindings']

    def __init__(self, file, sockets):
        self.file = file           # Path
        self.mode = 'detach'       # 'run' or 'detach' — defaults to detach
        self.sockets = sockets     # list of dicts from scan_sockets()
        self.bindings = {}         # local socket name -> canonical name (str)


class UIRow:
    """One renderable/selectable row in the export builder's flat list."""
    __slots__ = ['kind', 'data', 'layer_idx']

    def __init__(self, kind, data, layer_idx=None):
        self.kind = kind
        self.data = data
        self.layer_idx = layer_idx


def _is_dead_line(line):
    """True if this line is inert as far as the real .etcs engine is
    concerned — mirrors run_script's own '#' comment-skip rule exactly."""
    return line.lstrip().startswith('#')


def _parse_marker_line(path):
    """Parse this file's second line (right after the shebang) as either
    '#EXPORT [path]' or '#IMPORT path'.

    '#EXPORT' and '#IMPORT' are the SAME directive for resolution purposes
    -- both optionally declare one additional folder (beyond the local
    directory) that this file's own run/detach references may fall back
    to. They differ only in how the tool treats the file: '#EXPORT' marks
    it as a stack manifest (Tab / Stack Builder viewable); '#IMPORT' marks
    it as an ordinary leaf script (not stack-viewable -- a leaf has
    nothing to build a stack from).

    Returns (is_export, is_import, target_dir_or_None).

    Legacy tolerance: a bare '#EXPORT' with no path (the original marker
    format, before it could carry a folder) is still recognized as a
    stack anywhere in the first 3 lines, matching the tool's original
    leniency -- it simply carries no additional resolution folder, same
    as a file with no marker at all.
    """
    try:
        lines = Path(path).read_text(errors='replace').splitlines()
    except IOError:
        return False, False, None

    legacy_export = any(l.strip() == EXPORT_MARKER for l in lines[:3])

    if len(lines) < 2:
        return legacy_export, False, None

    line = lines[1].strip()

    for prefix, is_exp in ((EXPORT_MARKER, True), (IMPORT_MARKER_PREFIX, False)):
        if line == prefix or line.startswith(prefix + ' ') or line.startswith(prefix + '\t'):
            rest = line[len(prefix):].strip()
            target = _resolve_directive_target(rest, path) if rest else None
            return (is_exp or legacy_export), (not is_exp), target

    return legacy_export, False, None


def is_export_file(path):
    """True if this .etcs file is ITSELF a generated export — carries
    the '#EXPORT' marker (bare, or with a domain-folder path)."""
    is_exp, _, _ = _parse_marker_line(path)
    return is_exp


def is_export_entry(entry):
    """FileEntry-level convenience wrapper around is_export_file, with a
    legacy fallback for exports written before the marker existed."""
    if entry.is_dir or not entry.is_etcs:
        return False
    if entry.name.lower() == 'export.etcs':
        return True
    return is_export_file(entry.path)


def get_import_target(path):
    """Return the domain folder this file's run/detach references may
    additionally resolve against, declared on line 2 via either
    '#IMPORT <path>' or '#EXPORT <path>' -- the two are identical for
    resolution purposes (see _parse_marker_line), differing only in
    whether the tool also treats the file as a stack. Returns None if
    neither directive carries a path.

    This is a single-hop lookup only — it does not follow whatever
    directive the target folder's own files might separately declare.
    Every file's reference space is exactly "local directory + this one
    domain folder", readable from that file alone; nothing chains
    further at resolution time. See resolve_script_path's docstring for
    how this composes as execution moves from script to script.
    """
    _, _, target = _parse_marker_line(path)
    return target


def resolve_script_path(from_file, script_name):
    """Resolve a run/detach-style script reference the same way the real
    engine does: check the calling file's own directory first, then fall
    back to that file's single '#IMPORT' target folder, if it declared one.

    Each file's own #IMPORT is consulted independently — a chain of
    run/detach calls across several files does NOT inherit or accumulate
    import folders from its callers. Each file names at most one folder
    of its own, which is what keeps the whole arrangement "singly linked"
    (one link per node) rather than a search problem: the reference space
    for any given file is knowable by reading that one file alone.

    Returns the resolved Path whether or not it actually exists — callers
    that need existence should check separately, same as the real engine
    leaving that to the eventual file-open call.
    """
    base_dir = Path(from_file).resolve().parent
    local_candidate = (base_dir / script_name).resolve()
    if local_candidate.exists():
        return local_candidate

    import_dir = get_import_target(from_file)
    if import_dir is None:
        return local_candidate

    return (import_dir / script_name).resolve()


def compute_roots(dirpath):
    """Return the .etcs files in dirpath that nothing else in the same
    directory GENUINELY invokes."""
    dirpath = Path(dirpath)
    etcs_files = [
        f for f in dirpath.iterdir()
        if f.is_file()
        and f.suffix.lower() == '.etcs'
        and f.name.lower() != 'export.etcs'
        and not is_export_file(f)
    ]

    referenced = set()
    for f in etcs_files:
        try:
            content = f.read_text(errors='replace')
        except IOError:
            continue
        for line in content.splitlines():
            if _is_dead_line(line):
                continue
            match = ETCS_REF_PATTERN.search(line)
            if not match:
                continue
            ref_name = match.group(2)
            ref_path = resolve_script_path(f, ref_name)
            for ef in etcs_files:
                if ef.resolve() == ref_path:
                    referenced.add(ef.name)

    roots = [f for f in etcs_files if f.name not in referenced]
    roots.sort(key=lambda x: x.name.lower())
    return roots


_ace_root_cache = None
_ace_root_cache_computed = False


def get_ace_root():
    """Resolve the ace root directory via 'ace root'. Returns None if
    unavailable.

    Cached for this process's lifetime -- ACE_ROOT-relative directives
    call this on every affected run/detach resolution, browser listing,
    and export write, so re-spawning the subprocess each time would be
    far too hot a path.
    """
    global _ace_root_cache, _ace_root_cache_computed
    if _ace_root_cache_computed:
        return _ace_root_cache
    try:
        result = subprocess.run(
            ["ace", "root"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5
        )
        _ace_root_cache = result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        _ace_root_cache = None
    _ace_root_cache_computed = True
    return _ace_root_cache


def get_ace_shebang():
    """Resolve the '#!' interpreter line for a generated export.etcs."""
    root = get_ace_root()
    return f"{root}/bin/etcs" if root else None


ACE_ROOT_PLACEHOLDER = "ACE_ROOT"


def to_ace_root_relative(path):
    """Return path as 'ACE_ROOT/relative/sub/path' if 'ace root' is
    available and path lives under it; otherwise the absolute path
    unchanged, as a string.

    Used when WRITING a domain-folder directive (an export's own
    '#EXPORT <path>' line), so the resulting file is portable across any
    machine whose 'ace root' resolves to a tree with the same relative
    layout underneath it -- e.g. <root>/script, <root>/script/exports --
    rather than baking in one machine's absolute filesystem layout.
    """
    path = Path(path).resolve()
    root = get_ace_root()
    if root:
        try:
            rel = path.relative_to(Path(root).resolve())
        except ValueError:
            pass  # path isn't under the ace root -- fall through to absolute
        else:
            rel_str = rel.as_posix()
            return ACE_ROOT_PLACEHOLDER if rel_str == '.' else f"{ACE_ROOT_PLACEHOLDER}/{rel_str}"
    return str(path)


def _resolve_directive_target(raw_target, from_file):
    """Turn a directive's raw path text into an absolute Path.

    If raw_target is the 'ACE_ROOT' placeholder (bare, or with a
    following '/...'), it's resolved against the live 'ace root' command
    output -- portable across machines as long as 'ace root' resolves to
    a tree with the same relative layout. If 'ace root' isn't available,
    this directive can't be resolved and None is returned, which callers
    treat the same as "no directive present" (local-directory-only
    resolution).

    Otherwise, raw_target is treated as before: an absolute path is used
    as-is; a relative path is resolved against from_file's own directory.
    """
    if raw_target == ACE_ROOT_PLACEHOLDER or raw_target.startswith(ACE_ROOT_PLACEHOLDER + '/'):
        root = get_ace_root()
        if not root:
            return None
        remainder = raw_target[len(ACE_ROOT_PLACEHOLDER):].lstrip('/')
        return (Path(root) / remainder).resolve() if remainder else Path(root).resolve()

    target_path = Path(raw_target)
    if not target_path.is_absolute():
        target_path = (Path(from_file).resolve().parent / target_path).resolve()
    return target_path


def scan_sockets(filepath):
    """Best-effort STATIC scan for a .etcs file's exposed local socket names."""
    sockets = []
    seen_names = set()
    module_name = ""
    tag_name = ""
    started = False

    def add_socket(module, tag, name, line_no):
        if not module or not tag or not name or name in seen_names:
            return
        seen_names.add(name)
        sockets.append({'module': module, 'tag': tag, 'name': name, 'line': line_no})

    def is_local_name(tok):
        return bool(tok) and bool(re.match(r'^[A-Za-z0-9_]+$', tok)) and not tok.isdigit()

    try:
        raw_lines = Path(filepath).read_text(errors='replace').splitlines()
    except IOError:
        return sockets

    for line_no, raw in enumerate(raw_lines, 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue

        is_first_line = not started
        started = True

        sp = line.split(None, 1)
        verb = sp[0]
        rest = sp[1].strip() if len(sp) > 1 else ""

        if verb == 'context':
            if not rest:
                continue
            parts = rest.split(None, 1)
            scope = parts[0]
            name_tok = parts[1].strip() if len(parts) > 1 else ""
            if '::' in scope:
                mod, tg = scope.split('::', 1)
                module_name, tag_name = mod, tg
                if name_tok and is_local_name(name_tok):
                    add_socket(mod, tg, name_tok, line_no)
            elif scope[:1].isupper():
                module_name, tag_name = scope, ""
            continue

        if verb == 'spawn':
            if rest and '::' in rest:
                parts = rest.split(None, 1)
                mod, tg = parts[0].split('::', 1)
                module_name, tag_name = mod, tg
                if len(parts) > 1 and is_local_name(parts[1].strip()):
                    seen_names.add(parts[1].strip())
            elif rest and is_local_name(rest):
                seen_names.add(rest)
            continue

        if verb == 'as':
            # CmdBind (as name) calls ctx.bind(), which unconditionally
            # overwrites names[name] -- there is no existing-binding check,
            # exactly like explicit spawn's overwrite=true path above. That
            # means a name declared here can never actually receive an
            # external binding from a run/detach caller: injecting one
            # would just get clobbered the instant this line executes.
            # Record it so a later line can't mistakenly get treated as a
            # real socket under the same name, but don't expose this one
            # as bindable -- same treatment as spawn, for the same reason.
            if rest and is_local_name(rest):
                seen_names.add(rest)
            continue

        if verb.lower() in ('detach', 'run', 'signal', 'jobs', 'list', 'exit', 'quit'):
            continue

        if verb[:1].isupper() and '.' not in verb:
            if is_first_line or not module_name:
                module_name, tag_name = verb, ""
            elif not tag_name:
                tag_name = verb
                if rest and is_local_name(rest):
                    add_socket(module_name, tag_name, rest, line_no)
            continue

    return sockets


def suggest_canonical(stack, layer_idx, sock):
    """Look backward through already-stacked layers for a socket of the
    exact same (module, tag) type that the user has ALREADY given an
    explicit canonical binding to."""
    for earlier in reversed(stack[:layer_idx]):
        for esock in earlier.sockets:
            if esock['module'] == sock['module'] and esock['tag'] == sock['tag']:
                canon = earlier.bindings.get(esock['name'])
                if canon:
                    return canon
    return None


def parse_export_stack(filepath):
    """Parse an EXISTING #EXPORT file back into a (stack, referenced_files)
    pair the builder can resume editing from."""
    canonical_types = {}
    stack = []
    referenced = set()

    try:
        lines = Path(filepath).read_text(errors='replace').splitlines()
    except IOError:
        return stack, referenced

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith('#'):
            continue

        m = _CONTEXT_LINE_RE.match(line)
        if m:
            mod, tag, nm = m.group(1), m.group(2), m.group(3)
            canonical_types.setdefault(nm, (mod, tag))
            continue

        m = _RUN_DETACH_LINE_RE.match(line)
        if not m:
            continue
        mode, script_name, rest = m.group(1).lower(), m.group(2), m.group(3)

        script_path = resolve_script_path(filepath, script_name)
        referenced.add(script_path)

        sockets = scan_sockets(script_path) if script_path.exists() else []
        socket_names = {s['name'] for s in sockets}

        bindings = {}
        for token in rest.split():
            if '=' not in token:
                continue
            k, v = token.split('=', 1)
            bindings[k] = v
            if k not in socket_names:
                mod, tag = canonical_types.get(v, ("?", "?"))
                sockets.append({'module': mod, 'tag': tag, 'name': k, 'line': -1})
                socket_names.add(k)

        layer = StackLayer(script_path, sockets)
        layer.mode = 'run' if mode == 'run' else 'detach'
        layer.bindings = bindings
        stack.append(layer)

    return stack, referenced


# --- Deterministic, stable-per-name coloring for socket variable names ---
PALETTE_BASE = 30
_PALETTE_COLORS = [curses.COLOR_RED, curses.COLOR_GREEN, curses.COLOR_YELLOW,
                   curses.COLOR_BLUE, curses.COLOR_MAGENTA, curses.COLOR_CYAN,
                   curses.COLOR_WHITE]


def init_name_palette():
    for i, color in enumerate(_PALETTE_COLORS):
        try:
            curses.init_pair(PALETTE_BASE + i, color, -1)
        except curses.error:
            pass


def color_for_name(name):
    """Deterministic color-pair + bold flag for a local variable name."""
    if not name:
        return curses.color_pair(1)
    digest = hashlib.md5(name.encode('utf-8')).digest()
    idx = digest[0] % len(_PALETTE_COLORS)
    bold = bool(digest[1] & 1)
    attr = curses.color_pair(PALETTE_BASE + idx)
    return attr | curses.A_BOLD if bold else attr


def init_colors():
    """Initialize color pairs for the TUI."""
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN, -1)        # Normal text
    curses.init_pair(2, curses.COLOR_YELLOW, -1)      # Selection arrow / pending swap
    curses.init_pair(3, curses.COLOR_GREEN, -1)       # .etcs references / run mode
    curses.init_pair(4, curses.COLOR_RED, -1)         # Errors / detach mode / missing file
    curses.init_pair(5, curses.COLOR_MAGENTA, -1)     # Braces
    curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_WHITE)   # Selected ref
    curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_GREEN)  # Selected shebang
    curses.init_pair(8, curses.COLOR_WHITE, curses.COLOR_BLUE)   # Header/footer
    curses.init_pair(9, curses.COLOR_BLUE, -1)        # Comments
    curses.init_pair(10, curses.COLOR_WHITE, curses.COLOR_MAGENTA) # Selected etcs in browser
    curses.init_pair(11, curses.COLOR_YELLOW, curses.COLOR_BLUE)  # Selected dir in browser
    curses.init_pair(12, curses.COLOR_BLACK, curses.COLOR_WHITE)  # Free-scroll cursor
    curses.init_pair(13, curses.COLOR_WHITE, curses.COLOR_RED)    # Export.etcs highlight
    init_name_palette()


def safe_addstr(stdscr, y, x, text, attr=0):
    """Safely add string to screen, avoiding ERR on boundaries."""
    if y < 0 or x < 0:
        return
    max_y, max_x = stdscr.getmaxyx()
    if y >= max_y or x >= max_x:
        return
    avail = max_x - x
    if avail <= 0:
        return
    text = text[:avail]
    if not text:
        return
    try:
        stdscr.addstr(y, x, text, attr)
    except curses.error:
        pass


def curses_text_prompt(stdscr, y, x, prompt, initial=""):
    """Minimal in-place single-line text editor at (y, x)."""
    curses.curs_set(1)
    buf = list(initial)
    while True:
        safe_addstr(stdscr, y, x, " " * 60)
        safe_addstr(stdscr, y, x, prompt + ''.join(buf))
        try:
            stdscr.move(y, x + len(prompt) + len(buf))
        except curses.error:
            pass
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (curses.KEY_ENTER, 10, 13):
            curses.curs_set(0)
            return ''.join(buf)
        elif ch == 27:
            curses.curs_set(0)
            return None
        elif ch in (curses.KEY_BACKSPACE, 8, 127):
            if buf:
                buf.pop()
        elif 32 <= ch < 127:
            buf.append(chr(ch))


def prompt_export_name(stdscr, default="export"):
    """Prompt for the export's base name (no '.etcs' suffix)."""
    while True:
        stdscr.clear()
        safe_addstr(stdscr, 0, 0, " Export name (letters/digits/_/- only, no .etcs suffix) ",
                    curses.color_pair(8))
        stdscr.refresh()
        result = curses_text_prompt(stdscr, 2, 2, "Name: ", default)
        if result is None:
            return None
        name = result.strip()
        if name.lower().endswith('.etcs'):
            name = name[:-5]
        if not name:
            name = default
        if re.match(r'^[A-Za-z0-9_\-]+$', name):
            return name
        safe_addstr(stdscr, 4, 2, f" Invalid name '{name}' — letters, digits, _ and - only. ",
                    curses.color_pair(4) | curses.A_BOLD)
        stdscr.refresh()
        stdscr.getch()
        default = name


def build_rows(stack, available):
    """Flatten current stack + available scripts into one selectable list."""
    rows = []
    rows.append(UIRow('section', 'AVAILABLE (Enter/Right adds to stack)'))
    for p in available:
        rows.append(UIRow('available', p))
    rows.append(UIRow('section', 'STACK (execution order, top to bottom)'))
    if not stack:
        rows.append(UIRow('empty', '  (empty — add a script from AVAILABLE above)'))
    for li, layer in enumerate(stack):
        rows.append(UIRow('layer_header', layer, layer_idx=li))
        for sock in layer.sockets:
            rows.append(UIRow('socket', sock, layer_idx=li))
    return rows


def clamp_to_selectable(rows, idx):
    """Return the nearest row index whose kind is in SELECTABLE_KINDS."""
    if not rows:
        return 0
    idx = max(0, min(idx, len(rows) - 1))
    if rows[idx].kind in SELECTABLE_KINDS:
        return idx
    for i in range(idx, len(rows)):
        if rows[i].kind in SELECTABLE_KINDS:
            return i
    for i in range(idx, -1, -1):
        if rows[i].kind in SELECTABLE_KINDS:
            return i
    return idx


def move_selectable(rows, cursor, direction):
    """Step cursor by one selectable row in the given direction (+1/-1)."""
    idx = cursor
    while True:
        idx += direction
        if idx < 0 or idx >= len(rows):
            return cursor
        if rows[idx].kind in SELECTABLE_KINDS:
            return idx


def pop_layer(stack, available, idx):
    """Remove the stack layer at idx (any position)."""
    if 0 <= idx < len(stack):
        popped = stack.pop(idx)


def _link_export_to_ace_root(export_path, name):
    """Best-effort: symlink the just-written export file into <ace_root>/scripts/exports/."""
    root = get_ace_root()
    if not root:
        print("\n Note: 'ace root' unavailable — skipped central exports symlink.")
        return
    exports_dir = Path(root) / "scripts" / "exports"
    try:
        exports_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"\n Warning: could not create {exports_dir}: {e}")
        return
    link_path = exports_dir / f"{name}.etcs"
    try:
        if link_path.is_symlink():
            link_path.unlink()
        elif link_path.exists():
            print(f"\n Warning: {link_path} exists and is not a symlink — "
                  f"leaving it alone, skipped central exports symlink.")
            return
        os.symlink(export_path.resolve(), link_path)
        print(f"\n Linked: {link_path} -> {export_path.resolve()}")
    except OSError as e:
        print(f"\n Warning: could not create symlink at {link_path}: {e}")


def _write_export(dirpath, stack, name):
    """Write '<name>.etcs' from the stack. Returns (export_path, conflicts).

    Writing the file and editing it used to be one function. They are two
    different operations -- the run path needs the artifact on disk and must
    NOT tear down curses or open an editor -- so they are separate now, and
    _write_export_and_edit is the composition of the two.
    """
    dirpath = Path(dirpath)
    lines_out = []
    declared = set()
    name_types = {}
    conflicts = []
    declare_lines = []

    ace_path = get_ace_shebang()
    lines_out.append(f"#!{ace_path}" if ace_path else "#!/usr/bin/env etcs")
    # Always carry this export's own real source folder as its domain path
    # -- not just the bare marker. _link_export_to_ace_root below symlinks
    # this file into a central exports/ directory; when the interpreter
    # later runs it THROUGH that symlink, its origin path is the symlink's
    # location, not this one. Without a declared domain folder, local-only
    # resolution would look for every layer script next to the symlink and
    # find nothing. Declaring the real folder here means resolve_script_path
    # falls back to exactly the right place regardless of where this file
    # ends up being invoked from.
    lines_out.append(f"{EXPORT_MARKER} {to_ace_root_relative(dirpath)}")
    lines_out.append("# Auto-generated by etcs_viewer.py's export builder.")

    for layer in stack:
        for sock in layer.sockets:
            canonical = layer.bindings.get(sock['name'])
            if not canonical:
                continue
            typekey = (sock['module'], sock['tag'])
            if canonical in name_types and name_types[canonical] != typekey:
                prev_mod, prev_tag = name_types[canonical]
                conflicts.append(
                    f"'{canonical}' bound as {prev_mod}::{prev_tag} earlier, then "
                    f"again as {typekey[0]}::{typekey[1]} in {layer.file.name} — "
                    f"the second binding will NOT reach that entity at runtime."
                )
            else:
                name_types.setdefault(canonical, typekey)

            if canonical not in declared:
                declare_lines.append(f"context {sock['module']}::{sock['tag']} {canonical}")
                declare_lines.append(f"spawn {sock['module']}::{sock['tag']} {canonical}")
                declared.add(canonical)

    lines_out.extend(declare_lines)

    for layer in stack:
        binding_tokens = [
            f"{sock['name']}={layer.bindings[sock['name']]}"
            for sock in layer.sockets
            if layer.bindings.get(sock['name'])
        ]
        line = f"{layer.mode} {layer.file.name}"
        if binding_tokens:
            line += " " + " ".join(binding_tokens)
        lines_out.append(line)

    export_path = dirpath / f"{name}.etcs"
    export_path.write_text("\n".join(lines_out) + "\n", encoding='utf-8')
    os.chmod(export_path, 0o755)
    return export_path, conflicts


def _write_export_and_edit(dirpath, stack, name):
    """Write '<name>.etcs' from the finalized stack, then open $EDITOR."""
    export_path, conflicts = _write_export(dirpath, stack, name)

    curses.endwin()
    print(f"\n Wrote {export_path}\n")
    if conflicts:
        print(" Warning — name reused across different types:")
        for c in conflicts:
            print(f"   - {c}")
    _link_export_to_ace_root(export_path, name)
    edit_file(export_path)
    print(" Done.\n")


def switch_layer(stack, available, idx, new_file):
    """Replace the stack layer at idx with a freshly-scanned layer for new_file."""
    if not (0 <= idx < len(stack)):
        return
    old_mode = stack[idx].mode
    old_file = stack[idx].file
    new_layer = StackLayer(new_file, scan_sockets(new_file))
    new_layer.mode = old_mode
    stack[idx] = new_layer


# ---------------------------------------------------------------------------
# Export builder
#
# Two independently-scrolling panes (STACK above, AVAILABLE below), a cursor
# addressed in *units* rather than screen lines, and a block that is one unit
# no matter how many fragments it spans.
#
# Key model:
#   Up/Down          move one unit; falling off the bottom of STACK enters
#                    AVAILABLE, rising off the top of AVAILABLE re-enters STACK
#   Shift+Up/Down    switch pane (cancels any block, no swaps made)
#   Ctrl+Up/Down     block: create on the cursor fragment if none is active;
#                    extend/shrink the edge while the cursor is on the block;
#                    post the block before (Ctrl+Up) or after (Ctrl+Down) the
#                    highlighted fragment once the cursor has moved off it
#   Left/Backspace   in AVAILABLE, undo the last push; in STACK, delete the
#                    fragment under the cursor; with a block active, cancel it
#   Shift+Left       delete the next instance of the last-pushed fragment,
#                    scanning from the bottom -- repeatable
#   Enter/Right      push / toggle mode / edit a socket binding
#   d x s r q        duplicate, switch, save, run, quit
#
# Shift never touches the block. It is the pane key, so a block cannot survive
# a pane change: leaving STACK expands it back to full socket detail with
# nothing swapped.
# ---------------------------------------------------------------------------

_ARROW = {'A': 'up', 'B': 'down', 'C': 'right', 'D': 'left'}

_CSI_RE = re.compile(r"^\[(?:(\d+)(?:;(\d+))?)?([A-D])$")
_SS3_RE = re.compile(r"^O(?:(\d+);(\d+))?([A-D])$")
_RXVT_RE = re.compile(r"^([\[O])([a-d])$")
_KN_RE = re.compile(r"^k(UP|DN|LFT|RIT)(\d?)$")

_KN_ARROW = {'UP': 'up', 'DN': 'down', 'LFT': 'left', 'RIT': 'right'}
_KN_MODS = {
    '': {'shift'}, '2': {'shift'}, '3': {'alt'}, '4': {'shift', 'alt'},
    '5': {'ctrl'}, '6': {'ctrl', 'shift'}, '7': {'ctrl', 'alt'},
    '8': {'ctrl', 'alt', 'shift'},
}


def _put(win, y, x, text, attr=0):
    """Bounds-checked addstr for any window. Unlike safe_addstr this trims a
    write that would touch the bottom-right cell instead of losing the whole
    string to the curses.error it raises."""
    try:
        h, w = win.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        if x < 0:
            text = text[-x:]
            x = 0
        room = w - x
        if y == h - 1:
            room -= 1
        if room <= 0:
            return
        text = text[:room]
        if text:
            win.addstr(y, x, text, attr)
    except curses.error:
        pass


def _mods_from_param(param):
    """CSI modifier parameter -> modifier set. 1 + bitmask, shift=1 alt=2 ctrl=4."""
    mods = set()
    if not param:
        return mods
    try:
        bits = int(param) - 1
    except ValueError:
        return mods
    if bits & 1:
        mods.add('shift')
    if bits & 2:
        mods.add('alt')
    if bits & 4:
        mods.add('ctrl')
    return mods


def _decode_escape(stdscr):
    """Drain the tail of an escape sequence. Returns (name, mods)."""
    stdscr.nodelay(True)
    seq = []
    try:
        for _ in range(8):
            c = stdscr.getch()
            if c == -1:
                break
            seq.append(c)
    finally:
        stdscr.nodelay(False)

    if not seq:
        return 'esc', frozenset()

    s = "".join(chr(c) for c in seq if 0 <= c <= 0x10FFFF)

    m = _CSI_RE.match(s) or _SS3_RE.match(s)
    if m:
        return _ARROW[m.group(3)], frozenset(_mods_from_param(m.group(2)))

    m = _RXVT_RE.match(s)
    if m:
        return _ARROW[m.group(2).upper()], frozenset(
            {'ctrl'} if m.group(1) == 'O' else {'shift'})

    # Unrecognised: swallow it rather than ungetch-ing the tail and also
    # treating the ESC as a cancel, which fired spurious cancels and left
    # stray bytes in the queue.
    return 'unknown', frozenset()


def _read_key(stdscr):
    """Returns (name, mods, ch).

    Terminals report modified arrows three different ways depending on
    terminfo and TERM -- an ncurses extended keycode (kUP5), a shift keycode
    (KEY_SR), or a raw CSI sequence. All three are handled.
    """
    ch = stdscr.getch()

    if ch == 27:
        name, mods = _decode_escape(stdscr)
        return name, mods, None

    plain = {curses.KEY_UP: 'up', curses.KEY_DOWN: 'down',
             curses.KEY_LEFT: 'left', curses.KEY_RIGHT: 'right'}
    if ch in plain:
        return plain[ch], frozenset(), None

    for attr, nm in (('KEY_SR', 'up'), ('KEY_SF', 'down'),
                     ('KEY_SLEFT', 'left'), ('KEY_SRIGHT', 'right')):
        code = getattr(curses, attr, None)
        if code is not None and ch == code:
            return nm, frozenset({'shift'}), None

    if ch in (curses.KEY_ENTER, 10, 13):
        return 'enter', frozenset(), None
    if ch == 9:
        return 'tab', frozenset(), None
    if ch in (curses.KEY_BACKSPACE, 8, 127):
        return 'backspace', frozenset(), None
    if ch == curses.KEY_RESIZE:
        return 'resize', frozenset(), None

    try:
        kn = curses.keyname(ch).decode('ascii', 'replace')
    except Exception:
        kn = ''
    m = _KN_RE.match(kn)
    if m:
        return (_KN_ARROW[m.group(1)],
                frozenset(_KN_MODS.get(m.group(2), {'shift'})), None)

    if 0 <= ch < 256:
        return 'char', frozenset(), chr(ch)
    return 'unknown', frozenset(), None


# --- row / unit model ------------------------------------------------------
#
# A unit is one cursor stop. A fragment is a unit, each socket is a unit, and
# an active block is ONE unit spanning several rows. That is what stops the
# cursor landing inside a block and expanding from a member rather than from
# the block as a whole.

def _build_stack_rows(stack, blk):
    """Returns (rows, units). Sockets are hidden while a block is active --
    block mode is a modal move and socket rows are noise for picking a target."""
    rows, units = [], []
    i, n = 0, len(stack)
    while i < n:
        if blk is not None and blk[0] <= i <= blk[1]:
            u = len(units)
            units.append({'kind': 'block', 'lo': blk[0], 'hi': blk[1]})
            for j in range(blk[0], blk[1] + 1):
                rows.append({'kind': 'layer', 'layer_idx': j, 'unit': u})
            i = blk[1] + 1
            continue

        u = len(units)
        units.append({'kind': 'layer', 'layer_idx': i})
        rows.append({'kind': 'layer', 'layer_idx': i, 'unit': u})
        if blk is None:
            for k in range(len(stack[i].sockets)):
                units.append({'kind': 'socket', 'layer_idx': i, 'sock_idx': k})
                rows.append({'kind': 'socket', 'layer_idx': i,
                             'sock_idx': k, 'unit': len(units) - 1})
        i += 1
    return rows, units


def _unit_spans(rows):
    span = {}
    for ri, r in enumerate(rows):
        s = span.get(r['unit'])
        if s is None:
            span[r['unit']] = [ri, ri]
        else:
            s[1] = ri
    return span


def _unit_layer(u):
    return u['lo'] if u['kind'] == 'block' else u['layer_idx']


def _unit_for_layer(units, li):
    for ui, u in enumerate(units):
        if u['kind'] == 'block' and u['lo'] <= li <= u['hi']:
            return ui
        if u['kind'] in ('layer', 'socket') and u['layer_idx'] == li:
            return ui
    return 0


def _fit_scroll(scroll, first, last, height):
    if height <= 0:
        return 0
    if first < scroll:
        scroll = first
    if last > scroll + height - 1:
        scroll = last - height + 1
    return max(0, scroll)


def _relocate(stack, lo, hi, insert_at):
    """Lift stack[lo:hi+1] out and reinsert it starting at insert_at, where
    insert_at indexes the list *after* the segment was removed."""
    seg = stack[lo:hi + 1]
    del stack[lo:hi + 1]
    insert_at = max(0, min(insert_at, len(stack)))
    stack[insert_at:insert_at] = seg
    return insert_at, insert_at + len(seg) - 1


def _dup_layer(orig):
    dup = StackLayer(orig.file, orig.sockets)
    dup.mode = orig.mode
    dup.bindings = dict(orig.bindings)
    return dup


def _pending_unit(stack, pending):
    """Resolve an armed layer index to a cursor unit in the block-free view."""
    if pending is None or not stack:
        return None
    _, u2 = _build_stack_rows(stack, None)
    if not u2:
        return None
    return _unit_for_layer(u2, max(0, min(pending, len(stack) - 1)))


def _shift_left_target(stack, last_added, focus, units, stack_cursor,
                       available, avail_cursor):
    """What Shift+Left will drop.

    The push handle while it still matches something in the stack, otherwise
    whatever the cursor is pointing at. Plain Left stops at the bottom of the
    pushes it can undo -- that hard stop is deliberate. Shift+Left is the key
    that continues past it, so it must not go dead at the same boundary: once
    the handle is spent it falls through to the selection, and you can keep
    stripping instances up the stack without re-adding one first.
    """
    if last_added is not None and any(
            l.file.resolve() == last_added.resolve() for l in stack):
        return last_added
    if focus == 'avail' and available:
        return available[avail_cursor]
    if units and stack:
        li = _unit_layer(units[stack_cursor])
        if 0 <= li < len(stack):
            return stack[li].file
    return last_added


def _confirm_bar(stdscr, message):
    """One-line confirm on the bottom row. Enter or y confirms."""
    h, w = stdscr.getmaxyx()
    safe_addstr(stdscr, h - 1, 0, message[:w].ljust(w),
                curses.color_pair(2) | curses.A_BOLD)
    stdscr.refresh()
    ch = stdscr.getch()
    return ch in (curses.KEY_ENTER, 10, 13, ord('y'), ord('Y'))


def _edit_binding(stdscr, stack, unit, spans, cursor, scroll, pane_top):
    layer = stack[unit['layer_idx']]
    sock = layer.sockets[unit['sock_idx']]
    current = layer.bindings.get(sock['name'], "")
    if not current:
        suggestion = suggest_canonical(stack, unit['layer_idx'], sock)
        if suggestion:
            current = suggestion
    y_abs = pane_top + (spans[cursor][0] - scroll)
    result = curses_text_prompt(stdscr, y_abs, 2, f"{sock['name']} = ", current)
    stdscr.touchwin()
    if result is None:
        return
    if result.strip():
        layer.bindings[sock['name']] = result.strip()
    elif sock['name'] in layer.bindings:
        del layer.bindings[sock['name']]


def run_export_builder(stdscr, dirpath, initial_stack=None,
                       default_name="export", session_key=None):
    """Fully in-curses export.etcs stack builder."""
    curses.curs_set(0)
    stdscr.keypad(True)
    dirpath_resolved = Path(dirpath).resolve()

    # NOTE: this was named `key`, and the input read below also assigned to
    # `key` -- the session handle was clobbered on the first keystroke.
    sess_key = session_key if session_key is not None else dirpath_resolved

    if initial_stack is not None:
        stack = initial_stack
        _builder_sessions[sess_key] = stack
    else:
        stack = _builder_sessions.get(sess_key)
        if stack is None:
            stack = []
            _builder_sessions[sess_key] = stack

    available = compute_roots(dirpath_resolved)
    if not stack and not available:
        return None

    switch_pending = None
    last_added = None            # push handle: survives navigation, dies when
                                 # no instance of it is left in the stack
    block = None                 # raw (anchor, edge); normalised per frame
    focus = 'stack' if stack else 'avail'
    stack_cursor = 0
    avail_cursor = 0
    stack_scroll = 0
    avail_scroll = 0
    status = ""
    keyecho = False              # '?' -- report what each keypress decoded as
    last_key_desc = ""
    stack_reveal = None          # one-shot: bring this layer into view
    pending_cursor = None        # armed by a change made from the other pane;
                                 # consumed only by an IMMEDIATE switch into
                                 # STACK, cleared by any keystroke in between

    while True:
        # ---------------- normalise ----------------
        n = len(stack)
        if block is not None:
            if n == 0:
                block = None
            else:
                a, e = block
                block = (max(0, min(a, n - 1)), max(0, min(e, n - 1)))
        blk = (min(block), max(block)) if block is not None else None

        rows, units = _build_stack_rows(stack, blk)
        spans = _unit_spans(rows)

        stack_cursor = max(0, min(stack_cursor, len(units) - 1)) if units else 0
        avail_cursor = max(0, min(avail_cursor, len(available) - 1)) if available else 0

        if focus == 'stack' and not units:
            focus = 'avail'
        if focus == 'avail' and not available and units:
            focus = 'stack'
        # A block cannot outlive STACK focus.
        if focus != 'stack' and block is not None:
            block = None
            continue

        # ---------------- layout ----------------
        h, w = stdscr.getmaxyx()
        if h < 8 or w < 24:
            stdscr.erase()
            _put(stdscr, 0, 0, "terminal too small", curses.color_pair(4))
            stdscr.refresh()
            name, mods, chc = _read_key(stdscr)
            if name == 'esc' or (name == 'char' and chc in 'qQ'):
                return None
            continue

        content = max(2, h - 4)
        avail_h = max(1, min(content // 2, max(1, len(available))))
        stack_h = max(1, content - avail_h)
        avail_h = max(1, content - stack_h)

        stack_top = 2
        avail_title_y = 2 + stack_h
        avail_top = 3 + stack_h

        stack_win = curses.newwin(stack_h, w, stack_top, 0)
        avail_win = curses.newwin(avail_h, w, avail_top, 0)

        # ---------------- independent scroll ----------------
        # The STACK scroll follows its own cursor only while that pane holds
        # focus. With the cursor parked in AVAILABLE it is stationary by
        # design, and tying the view to it would put every push and drop below
        # the fold -- so those raise an explicit reveal instead, which moves
        # the view without moving the cursor.
        if units:
            if stack_reveal is not None and stack:
                ui = _unit_for_layer(units,
                                     max(0, min(stack_reveal, len(stack) - 1)))
                first, last = spans[ui]
                stack_scroll = _fit_scroll(stack_scroll, first, last, stack_h)
            elif focus == 'stack':
                first, last = spans[stack_cursor]
                stack_scroll = _fit_scroll(stack_scroll, first, last, stack_h)
            stack_scroll = max(0, min(stack_scroll, max(0, len(rows) - stack_h)))
        else:
            stack_scroll = 0
        stack_reveal = None
        if available:
            avail_scroll = _fit_scroll(avail_scroll, avail_cursor, avail_cursor, avail_h)
            avail_scroll = max(0, min(avail_scroll, max(0, len(available) - avail_h)))
        else:
            avail_scroll = 0

        # ---------------- chrome ----------------
        stdscr.erase()

        if blk is not None:
            size = blk[1] - blk[0] + 1
            header = (f" BLOCK ({size}) | Ctrl+Up/Down (or K/J) = grow · "
                      f"post to cursor | Right=mode | Esc=cancel ")
        elif switch_pending is not None:
            header = " SWITCH PENDING: pick in AVAILABLE + Enter | x/Esc=cancel "
        else:
            header = (" Tab=Viewer | Shift+Up/Down=pane | "
                      "Ctrl+Up/Down (or K/J)=block | Enter=push/bind | "
                      "Right=mode | d=dup x=switch s=save r=run ?=keys q=quit ")
        _put(stdscr, 0, 0, header[:w].ljust(w), curses.color_pair(8))

        s_title = f"─{'*' if focus == 'stack' else ' '} STACK ({n}) "
        a_title = f"─{'*' if focus == 'avail' else ' '} AVAILABLE ({len(available)}) "
        _put(stdscr, 1, 0, (s_title + "─" * w)[:w],
             curses.color_pair(6 if focus == 'stack' else 9) | curses.A_BOLD)
        _put(stdscr, avail_title_y, 0, (a_title + "─" * w)[:w],
             curses.color_pair(6 if focus == 'avail' else 9) | curses.A_BOLD)

        drop_target = _shift_left_target(stack, last_added, focus, units,
                                         stack_cursor, available, avail_cursor)
        if keyecho:
            footer = f" KEY: {last_key_desc or '(none yet)'} | ? to stop "
        elif status:
            footer = f" {status} "
        elif drop_target is not None and stack:
            footer = (f" {n} in stack | Shift+Left drops next "
                      f"'{drop_target.name}' from the bottom ")
        else:
            footer = f" {n} in stack | {len(available)} available "
        _put(stdscr, h - 1, 0, footer[:w].ljust(w), curses.color_pair(8))
        stdscr.noutrefresh()

        # ---------------- STACK pane ----------------
        stack_win.erase()
        for sy in range(stack_h):
            ri = stack_scroll + sy
            if ri >= len(rows):
                break
            row = rows[ri]
            u = row['unit']
            on_cursor = (u == stack_cursor)
            is_sel = on_cursor and focus == 'stack'
            is_ghost = on_cursor and focus != 'stack'
            in_block = (units[u]['kind'] == 'block')

            if row['kind'] == 'layer':
                li = row['layer_idx']
                layer = stack[li]
                missing = not layer.file.exists()
                mode_color = (curses.color_pair(4) if layer.mode == 'detach'
                              else curses.color_pair(3))

                label = f"[{li + 1}] {layer.file.name}"
                if switch_pending == li:
                    label += "  [SWITCH SOURCE]"
                if missing:
                    label += "  [MISSING FILE]"
                tag = f" {layer.mode.upper()} "

                if in_block:
                    prefix_attr = curses.color_pair(8) | curses.A_BOLD
                    label_color = curses.color_pair(8) | curses.A_BOLD
                    tag_color = curses.color_pair(8) | curses.A_BOLD
                    if is_sel:
                        label_color |= curses.A_REVERSE
                elif is_ghost:
                    prefix_attr = curses.color_pair(5) | curses.A_BOLD
                    label_color = curses.color_pair(5) | curses.A_BOLD
                    tag_color = curses.color_pair(5) | curses.A_BOLD
                elif is_sel:
                    prefix_attr = curses.color_pair(2) | curses.A_BOLD
                    label_color = curses.color_pair(6) | curses.A_BOLD
                    tag_color = curses.color_pair(6) | curses.A_BOLD
                else:
                    prefix_attr = curses.color_pair(1)
                    label_color = mode_color | curses.A_BOLD
                    tag_color = mode_color | curses.A_BOLD

                marker = "> " if (is_sel or is_ghost or in_block) else "  "
                _put(stack_win, sy, 0, marker, prefix_attr)
                _put(stack_win, sy, 2, label, label_color)
                _put(stack_win, sy, max(2 + len(label) + 2, w - len(tag) - 2),
                     tag, tag_color)

            else:  # socket
                # was reading a `layer` left over from an earlier iteration --
                # NameError whenever the pane started mid-fragment
                layer = stack[row['layer_idx']]
                sock = layer.sockets[row['sock_idx']]
                mapped = layer.bindings.get(sock['name'])
                if mapped:
                    suffix = f" = {mapped}"
                    color = color_for_name(mapped)
                else:
                    suffix = "  (unbound)"
                    color = curses.color_pair(1)
                if is_sel:
                    color |= curses.A_UNDERLINE
                elif is_ghost:
                    color = curses.color_pair(5)
                marker = "> " if (is_sel or is_ghost) else "  "
                lbl = f"  {sock['module']}::{sock['tag']} {sock['name']}{suffix}"
                _put(stack_win, sy, 0, marker,
                     curses.color_pair(5) if is_ghost else curses.color_pair(2))
                _put(stack_win, sy, 2, lbl, color)

        if len(rows) > stack_h:
            _put(stack_win, 0, w - 2, "^" if stack_scroll > 0 else " ",
                 curses.color_pair(9))
            _put(stack_win, stack_h - 1, w - 2,
                 "v" if stack_scroll + stack_h < len(rows) else " ",
                 curses.color_pair(9))
        stack_win.noutrefresh()

        # ---------------- AVAILABLE pane ----------------
        avail_win.erase()
        for sy in range(avail_h):
            ai = avail_scroll + sy
            if ai >= len(available):
                break
            p = available[ai]
            is_sel = (ai == avail_cursor and focus == 'avail')
            is_ghost = (ai == avail_cursor and focus != 'avail')
            if is_ghost:
                base = curses.color_pair(5) | curses.A_BOLD
                marker_attr = curses.color_pair(5)
                marker = "> "
            elif is_sel:
                base = curses.color_pair(6)
                marker_attr = curses.color_pair(2) | curses.A_BOLD
                marker = "> "
            else:
                base = curses.color_pair(3)
                marker_attr = curses.color_pair(1)
                marker = "  "
            _put(avail_win, sy, 0, marker, marker_attr)
            _put(avail_win, sy, 2, p.name, base)

        if len(available) > avail_h:
            _put(avail_win, 0, w - 2, "^" if avail_scroll > 0 else " ",
                 curses.color_pair(9))
            _put(avail_win, avail_h - 1, w - 2,
                 "v" if avail_scroll + avail_h < len(available) else " ",
                 curses.color_pair(9))
        avail_win.noutrefresh()

        curses.doupdate()

        # ---------------- input ----------------
        name, mods, chc = _read_key(stdscr)
        ctrl = 'ctrl' in mods
        shift = 'shift' in mods
        status = ""

        # Disarm by default. A change re-arms it on the way through, so the
        # target only survives to the very next keystroke -- which is exactly
        # "switched to immediately after the change was made". Anything else
        # in between is a gap, and the parked cursor keeps its place.
        prev_pending = pending_cursor
        pending_cursor = None
        last_key_desc = (f"{name} mods={'+'.join(sorted(mods)) or 'none'}"
                         + (f" char={chc!r}" if chc else ""))

        if name == 'char' and chc == '?':
            keyecho = not keyecho
            continue

        # K/J are exact aliases for Ctrl+Up/Ctrl+Down. Plain ASCII always
        # arrives intact, so block mode stays reachable on terminals that do
        # not report modified arrows distinguishably.
        if name == 'char' and chc == 'k':
            name = 'up'
        elif name == 'char' and chc == 'j':
            name = 'down'
        elif name == 'char' and chc == 'K':
            name, ctrl, shift = 'up', True, False
        elif name == 'char' and chc == 'J':
            name, ctrl, shift = 'down', True, False

        if name in ('resize', 'unknown', 'none'):
            continue

        # ---- cancel / quit ----
        if name == 'esc' or (name == 'char' and chc in 'qQ'):
            if block is not None:
                keep = blk[0]
                block = None
                _, u2 = _build_stack_rows(stack, None)
                stack_cursor = _unit_for_layer(u2, keep)
            elif switch_pending is not None:
                switch_pending = None
            else:
                return None
            continue

        if name == 'tab':
            return SWITCH_TO_VIEWER

        # ---- Ctrl+Up/Down: the whole of block mode ----
        if name in ('up', 'down') and ctrl:
            delta = -1 if name == 'up' else 1
            if not stack:
                status = "stack is empty"
            elif focus != 'stack':
                status = "Ctrl+Up/Down applies to the STACK pane"
            elif switch_pending is not None:
                status = "finish or cancel the switch first"
            elif block is None:
                li = _unit_layer(units[stack_cursor])
                block = (li, li)
                _, u2 = _build_stack_rows(stack, (li, li))
                stack_cursor = _unit_for_layer(u2, li)
            elif units[stack_cursor]['kind'] == 'block':
                # cursor still on the block -> grow or shrink the edge
                a, e = block
                e = max(0, min(e + delta, len(stack) - 1))
                block = (a, e)
                nb = (min(a, e), max(a, e))
                _, u2 = _build_stack_rows(stack, nb)
                stack_cursor = _unit_for_layer(u2, nb[0])
            else:
                # cursor moved off the block -> post, and commit
                lo, hi = blk
                li = _unit_layer(units[stack_cursor])
                size = hi - lo + 1
                li_after = li if li < lo else li - size
                insert_at = li_after + (0 if delta < 0 else 1)
                new_lo, _new_hi = _relocate(stack, lo, hi, insert_at)
                block = None
                _, u2 = _build_stack_rows(stack, None)
                stack_cursor = _unit_for_layer(u2, new_lo)
                if switch_pending is not None:
                    switch_pending = None
            continue

        # ---- Shift+Up/Down: pane switch. Never touches the block. ----
        if name in ('up', 'down') and shift:
            if focus == 'stack' and available:
                focus = 'avail'
                block = None
            elif focus == 'avail' and units:
                focus = 'stack'
                landed = _pending_unit(stack, prev_pending)
                if landed is not None:
                    stack_cursor = landed
            continue

        # ---- plain Up/Down ----
        if name in ('up', 'down'):
            delta = -1 if name == 'up' else 1
            if focus == 'stack':
                nxt = stack_cursor + delta
                if nxt < 0:
                    stack_cursor = 0
                elif nxt >= len(units):
                    if available:
                        focus = 'avail'
                        block = None
                    else:
                        stack_cursor = max(0, len(units) - 1)
                else:
                    stack_cursor = nxt
            else:
                nxt = avail_cursor + delta
                if nxt < 0:
                    if units:
                        focus = 'stack'
                        landed = _pending_unit(stack, prev_pending)
                        stack_cursor = (landed if landed is not None
                                        else len(units) - 1)
                elif nxt >= len(available):
                    avail_cursor = max(0, len(available) - 1)
                else:
                    avail_cursor = nxt
            continue

        # ---- Shift+Left: drop the next instance, bottom-up ----
        # Deliberately keeps going past the stop that plain Left honours.
        if name == 'left' and shift:
            target = _shift_left_target(stack, last_added, focus, units,
                                        stack_cursor, available, avail_cursor)
            if switch_pending is not None:
                status = "finish or cancel the switch first"
            elif target is None:
                status = "nothing to drop"
            else:
                for i in range(len(stack) - 1, -1, -1):
                    if stack[i].file.resolve() == target.resolve():
                        pop_layer(stack, available, i)
                        stack_reveal = i
                        pending_cursor = i
                        if switch_pending is not None and switch_pending > i:
                            switch_pending -= 1
                        break
                else:
                    status = f"no '{target.name}' left in the stack"
                if last_added is not None and not any(
                        l.file.resolve() == last_added.resolve() for l in stack):
                    last_added = None
            continue

        # ---- Left / Backspace ----
        if name in ('left', 'backspace'):
            if block is not None:
                keep = blk[0]
                block = None
                _, u2 = _build_stack_rows(stack, None)
                stack_cursor = _unit_for_layer(u2, keep)
            elif focus == 'avail':
                # undo the push: strictly the bottom of the stack
                if (last_added is not None and switch_pending is None and stack
                        and stack[-1].file.resolve() == last_added.resolve()):
                    pop_layer(stack, available, len(stack) - 1)
                    stack_reveal = len(stack) - 1
                    pending_cursor = len(stack) - 1
                    if not any(l.file.resolve() == last_added.resolve()
                               for l in stack):
                        last_added = None
                elif last_added is not None:
                    status = f"'{last_added.name}' is no longer at the bottom — Shift+Left"
            elif units:
                u = units[stack_cursor]
                li = _unit_layer(u)
                if 0 <= li < len(stack):
                    pop_layer(stack, available, li)
                    if switch_pending is not None:
                        if switch_pending == li:
                            switch_pending = None
                        elif switch_pending > li:
                            switch_pending -= 1
                    if last_added is not None and not any(
                            l.file.resolve() == last_added.resolve() for l in stack):
                        last_added = None
                    _, u2 = _build_stack_rows(stack, None)
                    stack_cursor = (_unit_for_layer(u2, min(li, len(stack) - 1))
                                    if u2 else 0)
            continue
 
        # ---- Right ----
        if name == 'right':
            if focus == 'avail' and available:
                if switch_pending is not None:
                    switch_layer(stack, available, switch_pending,
                                 available[avail_cursor])
                    _, u2 = _build_stack_rows(stack, None)
                    stack_cursor = _unit_for_layer(u2, switch_pending)
                    switch_pending = None
                    focus = 'stack'
                else:
                    f = available[avail_cursor]
                    stack.append(StackLayer(f, scan_sockets(f)))
                    last_added = f
                    stack_reveal = len(stack) - 1
                    pending_cursor = len(stack) - 1
            elif units:
                u = units[stack_cursor]
                if u['kind'] == 'block':
                    new_mode = 'run' if stack[u['lo']].mode == 'detach' else 'detach'
                    for i in range(u['lo'], u['hi'] + 1):
                        stack[i].mode = new_mode
                elif u['kind'] == 'layer':
                    layer = stack[u['layer_idx']]
                    layer.mode = 'run' if layer.mode == 'detach' else 'detach'
                elif u['kind'] == 'socket':
                    _edit_binding(stdscr, stack, u, spans, stack_cursor,
                                  stack_scroll, stack_top)
            continue
 
        # ---- Enter ----
        if name == 'enter':
            if focus == 'avail' and available:
                if switch_pending is not None:
                    switch_layer(stack, available, switch_pending,
                                 available[avail_cursor])
                    _, u2 = _build_stack_rows(stack, None)
                    stack_cursor = _unit_for_layer(u2, switch_pending)
                    switch_pending = None
                    focus = 'stack'
                else:
                    f = available[avail_cursor]
                    stack.append(StackLayer(f, scan_sockets(f)))
                    last_added = f
                    stack_reveal = len(stack) - 1
                    pending_cursor = len(stack) - 1
            elif units:
                u = units[stack_cursor]
                if u['kind'] == 'socket' and switch_pending is None:
                    _edit_binding(stdscr, stack, u, spans, stack_cursor,
                                  stack_scroll, stack_top)
            continue
 
        # ---- character commands ----
        if name == 'char':
            if chc in 'dD':
                if focus == 'stack' and units:
                    u = units[stack_cursor]
                    if u['kind'] == 'block':
                        lo, hi = u['lo'], u['hi']
                        copies = [_dup_layer(stack[i]) for i in range(lo, hi + 1)]
                        stack[hi + 1:hi + 1] = copies
                        if switch_pending is not None and switch_pending > hi:
                            switch_pending += len(copies)
                    else:
                        li = u['layer_idx']
                        stack.insert(li + 1, _dup_layer(stack[li]))
                        if switch_pending is not None and switch_pending > li:
                            switch_pending += 1
                        _, u2 = _build_stack_rows(stack, blk)
                        stack_cursor = _unit_for_layer(u2, li + 1)
 
            elif chc in 'xX':
                if block is not None:
                    status = "cancel the block first"
                elif switch_pending is not None:
                    switch_pending = None
                elif focus == 'stack' and units:
                    u = units[stack_cursor]
                    if u['kind'] in ('layer', 'socket'):
                        switch_pending = u['layer_idx']
 
            elif chc in 'sS':
                if block is not None:
                    status = "cancel the block first"
                elif stack and switch_pending is None:
                    nm = prompt_export_name(stdscr, default=default_name)
                    stdscr.touchwin()
                    if nm is not None:
                        _write_export_and_edit(dirpath_resolved, stack, nm)
                        return nm
 
            elif chc in 'rR':
                if block is not None:
                    status = "cancel the block first"
                elif not stack:
                    status = "nothing to run"
                elif switch_pending is not None:
                    status = "finish or cancel the switch first"
                else:
                    temp = f"{default_name}{TEMP_RUN_SUFFIX}"
                    if _confirm_bar(stdscr,
                                    f" Save and run {temp}.etcs?  "
                                    f"[Enter=yes  any other key=cancel] "):
                        status = run_stack_now(stdscr, dirpath_resolved,
                                               stack, temp)
                    stdscr.touchwin()
            continue
 
 
def _launch_export_builder(stdscr, dirpath, initial_stack=None, default_name="export", session_key=None):
    """Runs the builder and restores curses state afterward."""
    written_name = run_export_builder(stdscr, dirpath, initial_stack=initial_stack,
                                       default_name=default_name, session_key=session_key)
    stdscr = curses.initscr()
    curses.curs_set(0)
    stdscr.nodelay(False)
    stdscr.keypad(True)
    init_colors()
    return written_name, stdscr
 
 
def expand_etcs_file(filepath, indent_level=0, visited=None):
    """Expand a .etcs file and return list of LineInfo objects."""
    if visited is None:
        visited = set()
 
    filepath = Path(filepath).resolve()
 
    if filepath in visited:
        indent = '\t' * indent_level
        return [LineInfo(f"{indent}# [CIRCULAR: {filepath.name}]", indent_level)]
 
    if not filepath.exists():
        indent = '\t' * indent_level
        return [LineInfo(f"{indent}# [NOT FOUND: {filepath.name}]", indent_level)]
 
    visited = visited | {filepath}
    indent = '\t' * indent_level
    result = []
 
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            raw_lines = f.readlines()
    except IOError as e:
        return [LineInfo(f"{indent}# [ERROR: {e}]", indent_level)]
 
    for i, raw_line in enumerate(raw_lines):
        line = raw_line.rstrip('\n\r')
        match = ETCS_REF_PATTERN.search(line)
        is_shebang = (i == 0 and line.startswith('#!'))
 
        if match:
            ref_name = match.group(2)
            ref_path = resolve_script_path(filepath, ref_name)
 
            result.append(LineInfo(
                f"{indent}{line}", indent_level, source_path=filepath,
                is_ref=True, ref_path=ref_path, ref_name=ref_name,
                is_shebang=is_shebang
            ))
            result.append(LineInfo(f"{indent}{{", indent_level, is_open_brace=True))
 
            expanded = expand_etcs_file(ref_path, indent_level + 1, visited)
            result.extend(expanded)
 
            result.append(LineInfo(f"{indent}}}", indent_level, is_close_brace=True))
        else:
            result.append(LineInfo(
                f"{indent}{line}", indent_level, source_path=filepath,
                is_shebang=is_shebang
            ))
 
    return result
 
 
def get_selectable_indices(lines):
    """Return sorted list of indices that are selectable."""
    return [i for i, line in enumerate(lines) if line.is_shebang or line.is_ref]
 
 
def get_editor_command():
    """Get the preferred editor command, defaulting to nano."""
    return os.environ.get('EDITOR') or os.environ.get('VISUAL') or 'nano'
 
 
def edit_file(filepath):
    """Open a file in the user's editor and wait for completion."""
    editor = get_editor_command()
    cmd = editor.split()
    cmd.append(str(filepath))
    try:
        subprocess.run(cmd, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        try:
            subprocess.run(['nano', str(filepath)], check=True)
            return True
        except:
            return False
 
 
def get_directory_entries(dirpath):
    """Get sorted list of files and directories."""
    entries = []
    try:
        for entry in Path(dirpath).iterdir():
            if entry.name.startswith('.'):
                continue
            entries.append(FileEntry(
                name=entry.name,
                path=entry,
                is_dir=entry.is_dir(),
                is_etcs=entry.suffix.lower() == '.etcs'
            ))
    except PermissionError:
        pass
 
    def sort_key(e):
        if is_export_entry(e):
            return (0, "")
        if e.is_dir:
            return (1, e.name.lower())
        if e.is_etcs:
            return (2, e.name.lower())
        return (3, e.name.lower())
 
    return sorted(entries, key=sort_key)
 
 
def draw_viewer_line(stdscr, y, x, line_info, is_selected, is_free_scroll, max_width):
    """Draw a single viewer line with appropriate styling."""
    if y < 0 or y >= stdscr.getmaxyx()[0]:
        return
 
    if is_selected:
        if line_info.is_ref:
            color = curses.color_pair(6) | curses.A_BOLD
        elif line_info.is_shebang:
            color = curses.color_pair(7) | curses.A_BOLD
        elif is_free_scroll:
            color = curses.color_pair(12)
        else:
            color = curses.color_pair(6)
        safe_addstr(stdscr, y, x, "> ", curses.color_pair(2) | curses.A_BOLD)
        safe_addstr(stdscr, y, x + 2, line_info.text, color)
    else:
        safe_addstr(stdscr, y, x, "  ", curses.color_pair(1))
        if line_info.is_ref:
            color = curses.color_pair(3) | curses.A_BOLD
        elif line_info.is_shebang:
            color = curses.color_pair(3) | curses.A_BOLD
        elif line_info.is_open_brace or line_info.is_close_brace:
            color = curses.color_pair(5)
        elif '[CIRCULAR' in line_info.text or '[NOT FOUND' in line_info.text or '[ERROR' in line_info.text:
            color = curses.color_pair(4)
        elif line_info.text.strip().startswith('#'):
            color = curses.color_pair(9)
        else:
            color = curses.color_pair(1)
        safe_addstr(stdscr, y, x + 2, line_info.text, color)
 
 
def draw_browser_line(stdscr, y, x, entry, is_selected, max_width):
    """Draw a single browser line."""
    if y < 0 or y >= stdscr.getmaxyx()[0]:
        return
 
    if entry.is_dir:
        display = f"{entry.name}/"
    elif entry.is_etcs:
        display = entry.name
    else:
        display = entry.name
 
    is_export = is_export_entry(entry)
 
    if is_selected:
        if is_export:
            color = curses.color_pair(13) | curses.A_BOLD
        elif entry.is_etcs:
            color = curses.color_pair(10) | curses.A_BOLD
        elif entry.is_dir:
            color = curses.color_pair(11) | curses.A_BOLD
        else:
            color = curses.color_pair(6)
        safe_addstr(stdscr, y, x, "> ", curses.color_pair(2) | curses.A_BOLD)
        safe_addstr(stdscr, y, x + 2, display, color)
    else:
        safe_addstr(stdscr, y, x, "  ", curses.color_pair(1))
        if is_export:
            color = curses.color_pair(13) | curses.A_BOLD
        elif entry.is_etcs:
            color = curses.color_pair(3) | curses.A_BOLD
        elif entry.is_dir:
            color = curses.color_pair(5) | curses.A_BOLD
        else:
            color = curses.color_pair(1)
        safe_addstr(stdscr, y, x + 2, display, color)
 
 
def find_nearest_selectable(selectable, current, direction):
    """Find the nearest selectable index in the given direction."""
    if not selectable:
        return 0
    if current in selectable:
        pos = selectable.index(current)
        new_pos = pos + direction
        if 0 <= new_pos < len(selectable):
            return selectable[new_pos]
        return current
    else:
        if direction < 0:
            for i in range(len(selectable) - 1, -1, -1):
                if selectable[i] < current:
                    return selectable[i]
        else:
            for i in range(len(selectable)):
                if selectable[i] > current:
                    return selectable[i]
        return selectable[0] if direction > 0 else selectable[-1]
 
 
def try_restore_selection(lines, selectable, old_line_info, old_index):
    """Try to restore selection to a similar position after reload."""
    if not selectable:
        return 0, False
    if old_line_info.is_ref and old_line_info.ref_path:
        for i, line in enumerate(lines):
            if line.is_ref and line.ref_path == old_line_info.ref_path:
                if i in selectable:
                    return i, False
    elif old_line_info.is_shebang:
        if 0 in selectable:
            return 0, False
    if old_index in selectable:
        return old_index, False
    if selectable:
        return min(selectable, key=lambda x: abs(x - old_index)), False
    return 0, False
 
 
def run_viewer(stdscr, filepath, from_browser=False):
    """Run the script viewer mode."""
    filepath = Path(filepath).resolve()
    if not filepath.exists():
        return 1
 
    init_colors()
    
    # Cache whether this file is an export, to determine if Tab is allowed
    is_export = is_export_file(filepath)
 
    lines = expand_etcs_file(filepath)
    selectable = get_selectable_indices(lines)
    current_idx = selectable[0] if selectable else 0
    scroll_offset = 0
    free_scroll = False
 
    while True:
        height, width = stdscr.getmaxyx()
        content_height = height - 2
 
        if current_idx <= scroll_offset:
            scroll_offset = max(0, current_idx - 1)
        elif current_idx >= scroll_offset + content_height:
            scroll_offset = current_idx - content_height + 2
        max_scroll = max(0, len(lines) - content_height)
        scroll_offset = min(scroll_offset, max_scroll)
 
        stdscr.clear()
 
        # Conditionally show Tab=Stack in header if the file has #EXPORT
        if from_browser:
            tab_hint = " | Tab=Stack " if is_export else ""
            header = f" ETCS Viewer: {filepath.name} | Arrows Nav | Enter Edit | <- Back{tab_hint} | q Quit "
        else:
            tab_hint = " | Tab=Stack " if is_export else ""
            header = f" ETCS Viewer: {filepath.name} | Arrows Nav | Enter Edit{tab_hint} | q Quit "
        header = header[:width].ljust(width)
        safe_addstr(stdscr, 0, 0, header, curses.color_pair(8))
 
        for screen_y in range(content_height):
            line_idx = scroll_offset + screen_y
            if line_idx >= len(lines):
                break
            draw_viewer_line(stdscr, screen_y + 1, 0, lines[line_idx],
                           line_idx == current_idx, free_scroll, width)
 
        footer = ""
        if 0 <= current_idx < len(lines):
            line_info = lines[current_idx]
            if line_info.is_ref:
                footer = f" > {line_info.ref_path} "
            elif line_info.is_shebang:
                footer = f" > {filepath} (root) "
        if not footer:
            footer = f" {current_idx + 1}/{len(lines)} "
        footer = footer[:width].ljust(width)
        safe_addstr(stdscr, height - 1, 0, footer, curses.color_pair(8))
 
        stdscr.refresh()
 
        key = stdscr.getch()
 
        if key == ord('q') or key == ord('Q') or key == 27:
            return 0
        elif key == curses.KEY_LEFT or key == curses.KEY_BACKSPACE or key == 8 or key == 127:
            if from_browser:
                return 2
        elif key in (ord('r'), ord('R')):
            # Run the file being viewed. Same runtime peer as the builder's
            # 'r', so the REPL state is shared between the two views.
            h_, _w = stdscr.getmaxyx()
            safe_addstr(stdscr, h_ - 1, 0,
                        f" Run {Path(filepath).name}?  "
                        f"[Enter=yes  any other key=cancel] ".ljust(_w),
                        curses.color_pair(2) | curses.A_BOLD)
            stdscr.refresh()
            if stdscr.getch() in (curses.KEY_ENTER, 10, 13, ord('y'), ord('Y')):
                run_script_now(stdscr, filepath)
            stdscr.touchwin()
 
        elif key == 9:  # Tab
            if is_export:
                # Pass the file itself as the session key so unsaved stacks survive the toggle
                session_key = filepath.resolve()
                res, stdscr = _launch_export_builder(stdscr, filepath.parent, 
                                                    default_name=filepath.stem,
                                                    session_key=session_key)
                # Reload viewer contents (catches any finalizations done in the builder)
                lines = expand_etcs_file(filepath)
                selectable = get_selectable_indices(lines)
                current_idx = selectable[0] if selectable else 0
                scroll_offset = 0
                free_scroll = False
        elif key in (curses.KEY_DOWN, ord('j')):
            if free_scroll:
                if current_idx < len(lines) - 1:
                    current_idx += 1
            else:
                next_sel = find_nearest_selectable(selectable, current_idx, 1)
                if next_sel != current_idx:
                    current_idx = next_sel
                else:
                    if current_idx < len(lines) - 1:
                        free_scroll = True
                        current_idx += 1
        elif key in (curses.KEY_UP, ord('k')):
            if free_scroll:
                if current_idx > 0:
                    current_idx -= 1
                if lines[current_idx].is_ref or lines[current_idx].is_shebang:
                    free_scroll = False
            else:
                current_idx = find_nearest_selectable(selectable, current_idx, -1)
        elif key == curses.KEY_PPAGE:
            if free_scroll:
                current_idx = max(0, current_idx - content_height)
                if lines[current_idx].is_ref or lines[current_idx].is_shebang:
                    free_scroll = False
            else:
                if selectable and current_idx in selectable:
                    pos = selectable.index(current_idx)
                    current_idx = selectable[max(0, pos - content_height)]
        elif key == curses.KEY_NPAGE:
            if free_scroll:
                current_idx = min(len(lines) - 1, current_idx + content_height)
            else:
                if selectable and current_idx in selectable:
                    pos = selectable.index(current_idx)
                    new_pos = min(len(selectable) - 1, pos + content_height)
                    if new_pos == pos:
                        if current_idx < len(lines) - 1:
                            free_scroll = True
                            current_idx = min(len(lines) - 1, current_idx + content_height)
                    else:
                        current_idx = selectable[new_pos]
        elif key == curses.KEY_HOME:
            if selectable:
                current_idx = selectable[0]
                free_scroll = False
        elif key == curses.KEY_END:
            current_idx = len(lines) - 1
            if not (lines[current_idx].is_ref or lines[current_idx].is_shebang):
                free_scroll = True
            else:
                free_scroll = False
        elif key in (ord('\n'), curses.KEY_ENTER, 13):
            if 0 <= current_idx < len(lines):
                line_info = lines[current_idx]
                edit_path = None
                if line_info.is_ref:
                    edit_path = line_info.ref_path
                elif line_info.is_shebang:
                    edit_path = filepath
 
                if edit_path and Path(edit_path).exists():
                    old_line_info = line_info
                    old_index = current_idx
 
                    curses.endwin()
                    print(f"\n  Editing: {edit_path}\n")
                    edit_file(edit_path)
                    print(f"\n  Reloaded: {edit_path}\n")
 
                    stdscr = curses.initscr()
                    curses.curs_set(0)
                    stdscr.nodelay(False)
                    stdscr.keypad(True)
                    init_colors()
 
                    lines = expand_etcs_file(filepath)
                    selectable = get_selectable_indices(lines)
                    current_idx, free_scroll = try_restore_selection(lines, selectable, old_line_info, old_index)
                    scroll_offset = max(0, current_idx - 1)
 
    return 0
 
 
def run_browser(stdscr, start_dir=None):
    """Run the file browser mode."""
    current_dir = Path(start_dir).resolve() if start_dir else Path.cwd()
    entries = get_directory_entries(current_dir)
    current_idx = 0
    scroll_offset = 0
 
    init_colors()
 
    while True:
        height, width = stdscr.getmaxyx()
        content_height = height - 2
 
        if not entries:
            current_idx = 0
        elif current_idx >= len(entries):
            current_idx = len(entries) - 1
 
        if current_idx <= scroll_offset:
            scroll_offset = max(0, current_idx - 1)
        elif current_idx >= scroll_offset + content_height:
            scroll_offset = current_idx - content_height + 2
        max_scroll = max(0, len(entries) - content_height)
        scroll_offset = min(scroll_offset, max_scroll)
 
        stdscr.clear()
 
        header = f" ETCS Browser: {current_dir} "
        header = header[:width].ljust(width)
        safe_addstr(stdscr, 0, 0, header, curses.color_pair(8))
 
        if not entries:
            safe_addstr(stdscr, height // 2, 2, "  (empty directory)", curses.color_pair(9))
        else:
            for screen_y in range(content_height):
                entry_idx = scroll_offset + screen_y
                if entry_idx >= len(entries):
                    break
                draw_browser_line(stdscr, screen_y + 1, 0, entries[entry_idx],
                                entry_idx == current_idx, width)
 
        etcs_count = sum(1 for e in entries if e.is_etcs)
        dir_count = sum(1 for e in entries if e.is_dir)
        footer = f" {dir_count} dirs, {etcs_count} .etcs | Tab=Stack | e=Export | Arrows Nav | Enter Open | <- Up | q Quit | n New .etcs file | "
        footer = footer[:width].ljust(width)
        safe_addstr(stdscr, height - 1, 0, footer, curses.color_pair(8))
 
        stdscr.refresh()
 
        key = stdscr.getch()
 
        if key == ord('q') or key == ord('Q') or key == 27:
            return 0
            
        elif key == 9:  # Tab - Switch to Stack Mode
            dirpath_resolved = current_dir.resolve()
            initial_stack = _builder_sessions.get(dirpath_resolved)
            written_name, stdscr = _launch_export_builder(stdscr, current_dir, initial_stack=initial_stack)
            entries = get_directory_entries(current_dir)
            if current_idx >= len(entries):
                current_idx = max(0, len(entries) - 1)
            scroll_offset = 0
            
        elif key == ord('e') or key == ord('E'):
            dirpath_resolved = current_dir.resolve()
            initial_stack = _builder_sessions.get(dirpath_resolved)
            written_name, stdscr = _launch_export_builder(stdscr, current_dir, initial_stack=initial_stack)
            entries = get_directory_entries(current_dir)
            if current_idx >= len(entries):
                current_idx = max(0, len(entries) - 1)
            scroll_offset = 0
            
        elif key == ord('n') or key == ord('N'):
            curses.endwin()
            try:
                name = input("  New script name (no .etcs suffix, or leave empty to cancel): ").strip()
                if name:
                    if not name.lower().endswith('.etcs'):
                        name += '.etcs'
                    subprocess.run(["ace", "script", name])
            except Exception as e:
                print(f"  Error: {e}", file=sys.stderr)
            
            input("  Press Enter to continue...")
            
            stdscr = curses.initscr()
            curses.curs_set(0)
            stdscr.nodelay(False)
            stdscr.keypad(True)
            init_colors()
            entries = get_directory_entries(current_dir)
            if current_idx >= len(entries):
                current_idx = max(0, len(entries) - 1)
            scroll_offset = 0
            
        elif key in (curses.KEY_BACKSPACE, 8, 127, curses.KEY_LEFT):
            parent = current_dir.parent
            if parent != current_dir:
                current_dir = parent
                entries = get_directory_entries(current_dir)
                current_idx = 0
                scroll_offset = 0
        elif key in (curses.KEY_UP, ord('k')):
            if entries:
                current_idx = max(0, current_idx - 1)
        elif key in (curses.KEY_DOWN, ord('j')):
            if entries:
                current_idx = min(len(entries) - 1, current_idx + 1)
        elif key == curses.KEY_PPAGE:
            current_idx = max(0, current_idx - content_height)
        elif key == curses.KEY_NPAGE:
            current_idx = min(len(entries) - 1 if entries else 0, current_idx + content_height)
        elif key == curses.KEY_HOME:
            current_idx = 0
        elif key == curses.KEY_END:
            current_idx = len(entries) - 1 if entries else 0
        elif key in (ord('\n'), curses.KEY_ENTER, 13, curses.KEY_RIGHT):
            if entries and 0 <= current_idx < len(entries):
                entry = entries[current_idx]
                if entry.is_dir:
                    current_dir = entry.path
                    entries = get_directory_entries(current_dir)
                    current_idx = 0
                    scroll_offset = 0
                elif entry.is_etcs:
                    if is_export_entry(entry):
                        parsed_stack, _ = parse_export_stack(entry.path)
                        # Use file path as session key to preserve state on toggle
                        session_key = entry.path.resolve()
                        _builder_sessions[session_key] = parsed_stack
                        res, stdscr = _launch_export_builder(stdscr, current_dir, initial_stack=parsed_stack, default_name=entry.path.stem, session_key=session_key)
                        
                        if res == SWITCH_TO_VIEWER:
                            # User pressed Tab to toggle to raw .etcs view
                            result = run_viewer(stdscr, entry.path, from_browser=True)
                            if result == 0 or result == 2:
                                init_colors()
                                entries = get_directory_entries(current_dir)
                                if current_idx >= len(entries):
                                    current_idx = max(0, len(entries) - 1)
                                scroll_offset = 0
                            else:
                                return result
                        else:
                            # User exited normally or finalized
                            init_colors()
                            entries = get_directory_entries(current_dir)
                            if current_idx >= len(entries):
                                current_idx = max(0, len(entries) - 1)
                            scroll_offset = 0
                    else:
                        result = run_viewer(stdscr, entry.path, from_browser=True)
                        if result == 0 or result == 2:
                            init_colors()
                            entries = get_directory_entries(current_dir)
                            if current_idx >= len(entries):
                                current_idx = max(0, len(entries) - 1)
                            scroll_offset = 0
                        else:
                            return result
 
 
def main(stdscr):
    """Main entry point."""
    curses.curs_set(0)
    stdscr.nodelay(False)
    stdscr.keypad(True)
 
    if len(sys.argv) > 1:
        filepath = Path(sys.argv[1]).resolve()
        if not filepath.exists():
            return 1
        if filepath.is_dir():
            return run_browser(stdscr, filepath)
        elif is_export_file(filepath) or filepath.name.lower() == 'export.etcs':
            init_colors()
            stack, _referenced = parse_export_stack(filepath)
            # Use file path as session key to preserve state on toggle
            session_key = filepath.resolve()
            _builder_sessions[session_key] = stack
            res = run_export_builder(stdscr, filepath.parent,
                                initial_stack=stack, default_name=filepath.stem, session_key=session_key)
            if res == SWITCH_TO_VIEWER:
                return run_viewer(stdscr, filepath, from_browser=False)
            return 0
        else:
            return run_viewer(stdscr, filepath, from_browser=False)
    else:
        return run_browser(stdscr)
 
 
def print_usage():
    print("""
ETCS Script Viewer - Interactive TUI
 
Usage:
  etcs_viewer.py              - Open file browser in current directory
  etcs_viewer.py <path>       - Open .etcs file directly, or browse if directory
  etcs_viewer.py print <file> - Print the fully expanded .etcs file to standard out
                                (no TUI, just the exact indented text output)
 
Navigation (Browser):
  Up/Down or j/k    - Navigate files/folders
  Enter or Right    - Open folder or .etcs file
  Left or Backspace - Go up one directory
  Tab or e          - Open/Resume the interactive export stack builder
  q or Escape       - Quit
 
Navigation (Viewer):
  Up/Down or j/k    - Jump between .etcs references (auto free-scrolls at ends)
  Page Up/Down      - Jump by page
  Home/End          - Jump to first/last reference or line
  Enter             - Edit selected script
  Left or Backspace - Return to browser (when launched from browser)
  Tab               - Toggle to Stack Builder (ONLY if file has #EXPORT)
  q or Escape       - Quit
 
Export Builder:
  Up/Down             Move selection
  Tab                 Toggle back to the raw .etcs Viewer
  Enter (available)   Push that script onto the stack
  Right (available)   Same as Enter — push onto the stack
  Right (on a layer)  Toggle that layer's run / detach mode
  Left / Backspace    Pop that layer — ANY position, not just the top
  x (on a layer)      Mark that layer as a switch source
  Enter (available),
    while switch pending  Complete the switch into the pending position
  x / Escape,
    while switch pending  Cancel the pending switch
  Enter (socket)      Edit that layer's canonical binding in place
  s                   Save: name it, write it, symlink, then open $EDITOR
  q or Escape         Cancel (or cancel a pending switch first)
 
Environment Variables:
  $EDITOR or $VISUAL  - Preferred editor (default: nano)
""")
 
 
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ('-h', '--help'):
        print_usage()
        sys.exit(0)
 
    # Handle CLI print mode (bypasses curses entirely)
    if len(sys.argv) >= 3 and sys.argv[1] == 'print':
        filepath = Path(sys.argv[2]).resolve()
        if not filepath.exists():
            print(f"Error: File not found: {filepath}", file=sys.stderr)
            sys.exit(1)
        lines = expand_etcs_file(filepath)
        for line in lines:
            print(line.text)
        sys.exit(0)
 
    try:
        exit_code = curses.wrapper(main)
        sys.exit(exit_code)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        try:
            curses.endwin()
        except:
            pass
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
 
 

