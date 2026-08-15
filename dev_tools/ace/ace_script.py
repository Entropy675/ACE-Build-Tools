"""ace script subsystem.

Part of the `ace` dev tool, split by causal boundary: this file owns the
script surface and nothing else. Mixed into AceManager in ace_install.py --
all methods are `self`-bound and may call across subsystems through the one
assembled object, but each subsystem's *definition* lives in exactly one file.
"""
from pathlib import Path
import subprocess
import sys

from .ace_common import (CYAN, YELLOW, GREEN, RED, RESET, DIM)


class ScriptMixin:

    def create_script(self, target=None):
        """Launch the ETCS viewer, optionally passing a file or directory path."""
        # The viewer lives one level up from the ace/ package, in dev_tools/
        viewer_path = self.tool_root / "dev_tools" / "etcs_viewer.py"
        
        if not viewer_path.is_file():
            print(f"{RED}[-] Error: Could not find etcs_viewer.py at {viewer_path}{RESET}")
            sys.exit(1)

        cmd = [sys.executable, str(viewer_path)]
        if target:
            cmd.append(target)

        # Hand off to the curses TUI. subprocess.run inherits stdio by default,
        # so the viewer takes over the terminal cleanly and returns control here.
        try:
            return subprocess.run(cmd).returncode
        except Exception as e:
            print(f"{RED}[-] Failed to launch ETCS viewer: {e}{RESET}")
            sys.exit(1)
