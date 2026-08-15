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

    def create_script(self, viewer_args=None):
        """Launch the ETCS viewer, passing through any extra CLI args."""
        viewer_path = self.tool_root / "dev_tools" / "etcs_viewer.py"
        
        if not viewer_path.is_file():
            print(f"{RED}[-] Error: Could not find etcs_viewer.py at {viewer_path}{RESET}")
            sys.exit(1)

        cmd = [sys.executable, str(viewer_path)]
        if viewer_args:
            cmd.extend(viewer_args)

        # Hand off to the viewer. subprocess.run inherits stdio by default,
        # so the TUI or print mode takes over standard out cleanly.
        try:
            return subprocess.run(cmd).returncode
        except Exception as e:
            print(f"{RED}[-] Failed to launch ETCS viewer: {e}{RESET}")
            sys.exit(1)