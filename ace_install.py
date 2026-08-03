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
        self.ace_root = self.script_path.parent
        os.environ["ACE_ROOT"] = str(self.ace_root)

        self.allowed_make_targets = {
            'build', 'clean', 'test', 'install', 'all', 'help'
        }

        self.root_make_targets = {
            'all', 'modules', 'loaders', 'clean', 'clean_modules', 'clean_loaders'
        }


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
