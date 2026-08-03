"""ace registry subsystem.

Part of the `ace` dev tool, split by causal boundary: this file owns the
registry surface and nothing else. Mixed into AceManager in ace_install.py --
all methods are `self`-bound and may call across subsystems through the one
assembled object, but each subsystem's *definition* lives in exactly one file.
"""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import re

from .ace_common import (CYAN, YELLOW, GREEN, RED, RESET, DIM)


class RegistryMixin:

    def _get_registry_dir(self):
        """Return the persistent global registry directory, creating it if needed.
        
        Unix:    ~/.etcs_registry
        Windows: %APPDATA%\\etcs_registry
        """
        system = platform.system()
        if system == "Windows":
            base = Path(os.environ.get("APPDATA", Path.home()))
        else:
            base = Path.home()
        registry = base / ".etcs_registry"
        registry.mkdir(exist_ok=True)
        return registry

    def _registry_add(self, module_name, target_path):
        """Add or update a module entry in the global registry."""
        record = self._get_registry_dir() / module_name
        record.write_text(str(target_path))

    def _registry_remove(self, module_name):
        """Remove a module entry from the global registry."""
        record = self._get_registry_dir() / module_name
        if record.exists():
            record.unlink()

    def _registry_entries(self):
        """Return all registry entries as a list of (name, target_path) pairs.

        Skips dotfiles -- the registry directory also holds machine-scoped
        bookkeeping (.deps_checked), which is not a module entry.
        """
        entries = []
        for record in sorted(self._get_registry_dir().iterdir()):
            if record.is_file() and not record.name.startswith('.'):
                entries.append((record.name, Path(record.read_text().strip())))
        return entries

    def _replay_registry_to_modules(self, modules_dir):
        """Replay the global registry into modules_dir.

        Rules:
          - If a real (non-symlink) directory exists with the same name → skip silently.
            The native module shadows the registry entry; do not overwrite or delete either.
          - If a symlink already exists → skip (already active).
          - If the registry target no longer exists → skip with a warning.
          - Otherwise → create the symlink.

        Returns (replayed, shadowed, skipped) lists.
        """
        modules_dir.mkdir(exist_ok=True)
        replayed = []
        shadowed = []
        skipped  = []

        for name, target in self._registry_entries():
            link = modules_dir / name

            # Native module shadows this registry entry — leave both alone
            if link.exists() and not link.is_symlink():
                shadowed.append((name, target))
                continue

            # Already an active symlink — nothing to do
            if link.is_symlink():
                skipped.append(name)
                continue

            # Target no longer exists
            if not target.exists():
                print(f"  [!] Registry entry '{name}' target missing: {target}")
                skipped.append(name)
                continue

            os.symlink(target, link, target_is_directory=target.is_dir())
            replayed.append((name, target))

        return replayed, shadowed, skipped

    def registry_verify(self):
        """Walk the global registry and report the status of each entry.

        Reports:
          OK       — target exists and symlink is active in current tree
          SHADOWED — a native module in this tree shadows the registry entry
          MISSING  — target path no longer exists on disk
          INACTIVE — target exists but symlink not present in current tree

        Offers explicit deletion of MISSING entries interactively.
        """
        entries = self._registry_entries()
        modules_dir = self.ace_root / "modules"

        if not entries:
            print("  (registry is empty)")
            return

        print(f"\n--- ETCS Registry Verify ({len(entries)} entries) ---")

        missing = []
        for name, target in entries:
            link = modules_dir / name
            target_ok = target.exists()

            if not target_ok:
                status = f"{RED}MISSING{RESET}  "
                missing.append(name)
            elif link.exists() and not link.is_symlink():
                status = f"{YELLOW}SHADOWED{RESET} "
            elif link.is_symlink():
                status = f"{GREEN}OK{RESET}       "
            else:
                status = f"{DIM}INACTIVE{RESET} "

            print(f"  {status} {name}")
            print(f"           {DIM}{target}{RESET}")

        if missing:
            print(f"\n  {RED}{len(missing)} missing target(s) detected.{RESET}")
            for name in missing:
                record = self._get_registry_dir() / name
                target = Path(record.read_text().strip())
                answer = input(f"  Delete registry entry '{name}' ({target})? [y/N]: ").lower()
                if answer == 'y':
                    record.unlink()
                    print(f"  {GREEN}[+] Deleted: {name}{RESET}")
                else:
                    print(f"  [*] Kept: {name}")
        else:
            print(f"\n  {GREEN}All registry targets are present.{RESET}")
