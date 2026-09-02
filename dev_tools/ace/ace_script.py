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

    def list_scripts(self):
        """Show the script layout: compositions at the root, fragments by owner.

        The split is the point rather than the tidiness. A fragment belongs to
        the provider whose types it acts on, and it says so by living there --
        so a module carries its own scripts the way it carries its own headers,
        and `modules/<Name>/scripts` is what a generator would fill in. The
        root keeps only what genuinely spans providers, which makes a
        cross-module dependency visible as a folder it had to reach out of.
        """
        root = Path(self.ace_root)
        shown = 0

        composed = sorted((root / "scripts").glob("*.etcs")) if (root / "scripts").is_dir() else []
        print(f"\n{CYAN}compositions{RESET} {DIM}(scripts/ -- span more than one provider){RESET}")
        for f in composed:
            print(f"    {f.name}")
            shown += 1
        if not composed:
            print(f"    {DIM}none{RESET}")

        modules_dir = root / "modules"
        if modules_dir.is_dir():
            for mod in sorted(p for p in modules_dir.iterdir() if p.is_dir()):
                frags = sorted((mod / "scripts").glob("*.etcs")) if (mod / "scripts").is_dir() else []
                if not frags:
                    continue
                print(f"\n{CYAN}{mod.name}{RESET} {DIM}(modules/{mod.name}/scripts){RESET}")
                for f in frags:
                    print(f"    {f.name}")
                    shown += 1

        print(f"\n{GREEN}{shown}{RESET} script(s). "
              f"{DIM}Reference another provider's fragment as "
              f"<Provider>/scripts/<name>.etcs under #IMPORT ACE_ROOT/modules.{RESET}\n")
        return 0

    def create_script(self, viewer_args=None):
        """Launch the ETCS viewer, passing through any extra CLI args."""
        viewer_path = self.tool_root / "dev_tools" / "etcs_viewer.py"
        
        if not viewer_path.is_file():
            print(f"{RED}[-] Error: Could not find etcs_viewer.py at {viewer_path}{RESET}")
            sys.exit(1)

        cmd = [sys.executable, str(viewer_path)]
        if viewer_args:
            cmd.extend(viewer_args)
        else:
            # No target: open at the root's compositions, which is where a
            # session starts. Module fragments are one directory down from
            # there and the browser walks into them.
            root_scripts = Path(self.ace_root) / "scripts"
            if root_scripts.is_dir():
                cmd.append(str(root_scripts))

        # Hand off to the viewer. subprocess.run inherits stdio by default,
        # so the TUI or print mode takes over standard out cleanly.
        try:
            return subprocess.run(cmd).returncode
        except Exception as e:
            print(f"{RED}[-] Failed to launch ETCS viewer: {e}{RESET}")
            sys.exit(1)