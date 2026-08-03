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
    LifecycleMixin
)

class AceManager(RegistryMixin, DepsMixin, AbiMixin, BuildMixin,
                 LifecycleMixin):
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

    def _find_etcs_root(self):
        """Locate the ETCS project root.

        The ace tool no longer lives inside the ETCS tree, so the root is
        discovered rather than assumed to be the tool's own directory:
          1. $ETCS_ROOT if it points at a real directory
          2. an upward search from the current directory, then the tool
             directory, for ETCS.h (the project entry point)
        Falls back (with a warning) to the current directory so path-based
        commands fail with their own clear message rather than crashing here.
        """
        env = os.environ.get("ETCS_ROOT")
        if env:
            p = Path(env).expanduser().resolve()
            if p.is_dir():
                return p
            print(f"{YELLOW}[!] ETCS_ROOT={env} is not a directory; searching instead.{RESET}")

        def looks_like_root(d):
            # ETCS.h is the public entry point at the base of the ETCS project,
            # so its presence marks the root unambiguously -- and a subproject
            # (which has its own Makefile) won't carry it, so the search keeps
            # walking up to the real root rather than stopping short.
            return (d / "ETCS.h").is_file()

        seen = set()
        for start in (Path.cwd(), self.script_path.parent):
            d = start.resolve()
            while d not in seen:
                seen.add(d)
                if looks_like_root(d):
                    return d
                if d.parent == d:
                    break
                d = d.parent

        print(f"{YELLOW}[!] Could not locate the ETCS root "
              f"(no ETCS.h found in this directory or any parent).{RESET}")
        print(f"{DIM}    Set ETCS_ROOT, run ace from inside the ETCS tree, or add a .etcs-root "
              f"marker at the project root. Falling back to the current directory.{RESET}")
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
        print("           | script <name>")
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
        elif cmd == "script" and len(args) > 1:         ace.create_script(args[1])  # <<< NEW
        else:
            print(f"[-] Unknown or incomplete command: '{cmd}'")
            sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
