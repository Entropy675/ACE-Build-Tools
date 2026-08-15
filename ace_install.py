#!/usr/bin/env python3
"""ace -- ETCS dev tool.

The command surface and the AceManager class, assembled from one mixin per
subsystem. Each subsystem's methods are DEFINED in its own file (ace_registry,
ace_deps, ace_abi, ace_build, ace_lifecycle); this file only composes them and
routes the CLI. The split is by causal boundary -- a subsystem talks to the
rest through `self` on the one assembled object, but its definition lives in
exactly one place.

Layout (all under dev_tools/):
    ace_install.py   <- this file: class assembly + CLI dispatch
    ace_common.py    <- shared ANSI colours
    ace_registry.py  <- global module registry
    ace_deps.py      <- machine dependency probing
    ace_abi.py       <- ABI introspection, drift, column compositor
    ace_build.py     <- make dispatch + arg validation
    ace_lifecycle.py <- install/uninstall/setup/remove/stage/scaffold
    ace_script.py    <- proxy for etcs_viewer.py script editor
"""
import os
import sys
from pathlib import Path

from dev_tools.ace import (
    CYAN, YELLOW, GREEN, RED, RESET, DIM,
    RegistryMixin,
    DepsMixin,
    AbiMixin,
    BuildMixin,
    LifecycleMixin,
    ScriptMixin
)

class AceManager(RegistryMixin, DepsMixin, AbiMixin, BuildMixin,
                 LifecycleMixin, ScriptMixin):
    """Assembled from the subsystem mixins. Method resolution runs left to
    right across the bases; none of them define colliding names (verified at
    split time), so the order is for readability, not disambiguation."""

    def __init__(self):
        self.script_path = Path(__file__).resolve()
        self.tool_root = self.script_path.parent   # where the ace tool itself lives
        self._ace_root = None                       # ETCS project root, discovered lazily on first use

        self.allowed_make_targets = {
            'build', 'clean', 'test', 'install', 'all', 'help'
        }

        self.root_make_targets = {
            'all', 'modules', 'loaders', 'clean', 'clean_modules', 'clean_loaders'
        }

    @property
    def ace_root(self):
        """The ETCS project root, discovered on first access and cached.

        Lazy so commands that don't need the ETCS tree (e.g. `script`) never
        trigger the search or its warning. Exported to the environment for
        child processes (make) the first time it resolves.
        """
        if self._ace_root is None:
            self._ace_root = self._find_etcs_root()
            os.environ["ACE_ROOT"] = str(self._ace_root)
            os.environ["ETCS_ROOT"] = str(self._ace_root)
        return self._ace_root

    @staticmethod
    def _is_etcs_root(d):
        """A directory is the ETCS root iff it carries ETCS.h (the entry point)."""
        try:
            path = Path(d)
            return path.name == "ETCS" and (Path(d) / "ETCS.h").is_file()
        except OSError:
            return False

    def _root_cache_path(self):
        base = os.environ.get("XDG_CACHE_HOME")
        return (Path(base) if base else Path.home() / ".cache") / "ace" / "etcs_root"

    def _read_root_cache(self):
        try:
            p = self._root_cache_path()
            if p.is_file():
                txt = p.read_text().strip()
                return Path(txt) if txt else None
        except OSError:
            pass
        return None

    def _write_root_cache(self, path):
        try:
            p = self._root_cache_path()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(str(Path(path).resolve()))
        except OSError:
            pass

    @staticmethod
    def _safe_subdirs(d):
        """Immediate subdirectories of d, skipping hidden ones and unreadable dirs."""
        try:
            return [c for c in d.iterdir() if c.is_dir() and not c.name.startswith(".")]
        except OSError:
            return []

    # directory names never worth descending into during the filesystem walk
    _WALK_SKIP = {".git", "node_modules", "__pycache__", "obj", "build", "dist",
                  ".cache", "venv", ".venv", "target", ".mypy_cache", ".pytest_cache"}

    def _bfs_for_root(self, base, max_dirs=4000, max_depth=5):
        """Bounded breadth-first walk under `base` for a directory carrying ETCS.h.
        Uses its own visited set (independent of the ancestor/sibling pass) so it
        actually descends subtrees that pass only glanced at. Bounded in both
        breadth (max_dirs scanned) and depth so it can never crawl the whole disk."""
        visited = set()
        queue = [(base, 0)]
        scanned = 0
        while queue and scanned < max_dirs:
            d, depth = queue.pop(0)
            if d in visited:
                continue
            visited.add(d)
            scanned += 1
            if self._is_etcs_root(d):
                return d
            if depth >= max_depth:
                continue
            for c in self._safe_subdirs(d):
                if c.name not in self._WALK_SKIP and c not in visited:
                    queue.append((c, depth + 1))
        return None

    def _search_etcs_root(self):
        """Find the ETCS root without assuming it is an ancestor of the tool.

        Phase 1: from cwd and the tool dir, walk up; at each level also check the
        siblings, so an ETCS tree sitting *beside* the tool (../ETCS/ETCS.h) is
        found. Phase 2: a bounded filesystem walk under a few bases, for a tree
        that has been relocated off the ancestor/sibling line.
        """
        checked = set()
        starts = []
        for s0 in (Path.cwd(), self.script_path.parent):
            r = s0.resolve()
            if r not in starts:
                starts.append(r)

        for start in starts:
            d = start
            while True:
                if d not in checked:
                    checked.add(d)
                    if self._is_etcs_root(d):
                        return d
                    for sib in self._safe_subdirs(d.parent):
                        if sib not in checked:
                            checked.add(sib)
                            if self._is_etcs_root(sib):
                                return sib
                if d.parent == d:
                    break
                d = d.parent

        bases = []
        for b in (self.script_path.parent.parent, Path.cwd().parent, Path.home()):
            rb = b.resolve()
            if rb not in bases:
                bases.append(rb)
        for base in bases:
            hit = self._bfs_for_root(base)
            if hit:
                return hit
        return None

    def _find_etcs_root(self):
        """Locate the ETCS project root (the directory containing ETCS.h).

        The tool may live anywhere -- inside the ETCS tree, beside it, or off on
        its own -- so resolution never assumes a parent relationship. A resolved
        path is cached; if $ETCS_ROOT or the cache points somewhere that no longer
        contains ETCS.h (the ETCS system moved or was deleted), that hint is
        discarded and the search re-runs, then the new location is re-cached.
        """
        # 1. explicit override, honoured only while it still holds ETCS.h
        env = os.environ.get("ETCS_ROOT")
        if env:
            p = Path(env).expanduser().resolve()
            if self._is_etcs_root(p):
                return p
            print(f"{YELLOW}[!] ETCS_ROOT={env} no longer contains ETCS.h; re-resolving.{RESET}")

        # 2. last known location, re-validated (handles a moved ETCS tree)
        cached = self._read_root_cache()
        if cached and self._is_etcs_root(cached):
            return cached.resolve()
        if cached:
            print(f"{DIM}[i] Cached ETCS root {cached} is gone; searching for its new location.{RESET}")

        # 3. discover it (ancestors, siblings, then a bounded walk)
        found = self._search_etcs_root()
        if found:
            found = found.resolve()
            self._write_root_cache(found)
            return found

        print(f"{YELLOW}[!] Could not locate the ETCS root "
              f"(no directory containing ETCS.h found near the tool or the cwd).{RESET}")
        print(f"{DIM}    Set ETCS_ROOT to the directory containing ETCS.h, or run ace from "
              f"inside/near the ETCS tree. Falling back to the current directory.{RESET}")
        return Path.cwd()


if __name__ == "__main__":
    ace = AceManager()
    args = sys.argv[1:]
    if not args:
        print("Usage: ace { install | uninstall | list | setup <mod> [OS] | remove <mod> | stage <mod> <dest> }")
        print("           | make { all | modules | loaders | clean | clean modules | clean loaders }")
        print("           | make { module <n> | clean module <n> }")
        print("           | make { loader <n> | clean loader <n> }")
        print("           | registry verify")
        print("           | deps { check | install | arch }")
        print("           | abi [module]")
        print("           | script [name]")
        sys.exit(0)

    cmd = args[0]
    try:
        if   cmd == "install":                          ace.install()
        elif cmd == "uninstall":                        ace.uninstall()
        elif cmd == "root":                             ace.print_root()
        elif cmd == "list":                             ace.list_modules()
        elif cmd == "setup" and len(args) > 1:          ace.setup(args[1], args[2] if len(args) > 2 else "default")
        elif cmd == "remove" and len(args) > 1:         ace.remove(args[1])
        elif cmd == "make":                             ace.make(args[1:])
        elif cmd == "stage" and len(args) > 2:          ace.stage(args[1], args[2])
        elif cmd == "registry" and args[1:] == ["verify"]: ace.registry_verify()
        elif cmd == "deps":                             ace.deps(args[1:])
        elif cmd == "abi":                              ace.abi(args[1:])
        elif cmd == "script":                           ace.create_script(args[1] if len(args) > 1 else None) 
        else:
            print(f"[-] Unknown or incomplete command: '{cmd}'")
            sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
