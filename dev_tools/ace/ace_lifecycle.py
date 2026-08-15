"""ace lifecycle subsystem.

Part of the `ace` dev tool, split by causal boundary: this file owns the
lifecycle surface and nothing else. Mixed into AceManager in ace_install.py --
all methods are `self`-bound and may call across subsystems through the one
assembled object, but each subsystem's *definition* lives in exactly one file.
"""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import re
import sys

from .ace_common import (CYAN, YELLOW, GREEN, RED, RESET, DIM)


class LifecycleMixin:

    def _scrub_env_unix(self, key):
        """Clean export lines from shell profiles."""
        home = Path.home()
        profiles = [home / ".bashrc", home / ".zshrc", home / ".bash_profile"]
        pattern = rf'^\s*export\s+{key}\s*=.*$'
        for profile in profiles:
            if profile.exists():
                try:
                    content = profile.read_text()
                    if re.search(pattern, content, flags=re.MULTILINE):
                        new_content = re.sub(pattern, '', content, flags=re.MULTILINE).strip()
                        profile.write_text(new_content + '\n')
                except Exception as e:
                    print(f"  [!] Could not scrub {profile.name}: {e}")

    def _delayed_self_destruct(self, path, system):
        """Spawn a background process to delete the root after exit."""
        if system == "Windows":
            cmd = f'timeout /t 2 && rd /s /q "{path}"'
        else:
            cmd = f'sleep 1 && rm -rf "{path}"'
        subprocess.Popen(cmd, shell=True)

    def _confirm(self, message, silent):
        if silent: return True
        return input(f"{message} [y/N]: ").lower() == 'y'

    def print_root(self):
        print(self.ace_root)

    def install(self, silent=False):
        """Install ace globally via symlink or shim, then replay the global registry."""
        system = platform.system()
        print(f"--- ACE Installation: {system} ---")

        # Dependency check runs FIRST, before anything is forged: a fresh
        # clone on a new machine should learn what it needs before it starts
        # placing global hooks that assume a working toolchain.
        self._deps_first_run(silent=silent)

        if system == "Windows":
            bin_dir = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/WindowsApps"
            target_link = bin_dir / "ace_logic.py"
            shim = bin_dir / "ace.bat"
        else:
            bin_dir = Path("/usr/local/bin")
            target_link = bin_dir / "ace"

        # Show what's in the registry before forging
        entries = self._registry_entries()
        if entries:
            print(f"[*] Global registry has {len(entries)} external module(s) — will replay into modules/")
        else:
            print(f"[*] Global registry is empty.")

        if not self._confirm(f"Forge global hook at {target_link}?", silent): return

        # --- Forge the new global hook ---
        try:
            if not bin_dir.exists(): bin_dir.mkdir(parents=True, exist_ok=True)
            if target_link.exists() or target_link.is_symlink(): os.remove(target_link)

            os.symlink(self.script_path, target_link)
            if system == "Windows":
                with open(shim, "w") as f: f.write(f"@echo off\npython \"{target_link}\" %*")
            else:
                target_link.chmod(0o755)
            print(f"[+] Global hook forged: {target_link}")
        except PermissionError:
            print("[-] Error: Permission denied. (Try running as Admin/Sudo)"); return

        # --- Forge the etcs runtime symlink ---
        etcs_binary = self.ace_root / "bin" / "etcs"
        etcs_link = bin_dir / "etcs"
        
        if etcs_binary.exists():
            try:
                if etcs_link.exists() or etcs_link.is_symlink():
                    os.remove(etcs_link)
                os.symlink(etcs_binary, etcs_link)
                if system != "Windows":
                    etcs_link.chmod(0o755)
                print(f"[+] ETCS runtime forged: {etcs_link}")
            except PermissionError:
                print(f"[-] Error: Permission denied linking etcs runtime. (Try running as Admin/Sudo)")
        else:
            print(f"[*] ETCS binary not found at {etcs_binary}, skipping runtime link.")

        # --- Replay registry into this tree's modules/ ---
        if entries:
            modules_dir = self.ace_root / "modules"
            replayed, shadowed, skipped = self._replay_registry_to_modules(modules_dir)

            if replayed:
                print(f"[+] Restored {len(replayed)} external module(s):")
                for name, target in replayed:
                    print(f"    {GREEN}{name}{RESET} {DIM}-> {target}{RESET}")

            if shadowed:
                print(f"  [*] {len(shadowed)} shadowed by native module(s) — left untouched:")
                for name, target in shadowed:
                    print(f"    {YELLOW}{name}{RESET} {DIM}(registry: {target}){RESET}")

            if skipped:
                print(f"  [*] {len(skipped)} already active or missing — skipped.")

    def uninstall(self, silent=False):
        """Remove global links and optionally nuke module source.
        
        The global registry is never touched — it persists across uninstalls.
        """
        system = platform.system()
        root_dir = self.ace_root
        modules_dir = root_dir / "modules"

        print(f"--- ⚠️  ACE TOTAL UNINSTALL ⚠️  ---")
        print(f"[*] Global registry at {self._get_registry_dir()} will be preserved.")
        if not self._confirm("This will remove ACE and all global hooks. Proceed?", silent):
            return

        # --- Remove symlinked modules (optionally nuke source) ---
        if modules_dir.exists():
            active_modules = [m for m in modules_dir.iterdir() if m.is_symlink()]
            if active_modules:
                nuke_source = self._confirm(f"DELETE source code for {len(active_modules)} module(s)?", silent)
                for mod_link in active_modules:
                    if nuke_source:
                        try:
                            target_dir = mod_link.resolve()
                            etcs_link = target_dir.parent / "ETCS"
                            if etcs_link.is_symlink(): etcs_link.unlink()

                            if len(target_dir.parts) <= 3:
                                print(f"  [!] Safety triggered: refusing to delete shallow path {target_dir}")
                                continue

                            shutil.rmtree(target_dir)
                            print(f"  [+] Obliterated: {mod_link.name}")
                        except Exception as e:
                            print(f"  [!] Failed to nuke {mod_link.name}: {e}")
                    mod_link.unlink()

        # --- Remove global hooks ---
        bin_dir = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/WindowsApps" if system == "Windows" else Path("/usr/local/bin")
        
        # ADDED: 'etcs' to the list of targets to remove
        if system == "Windows":
            targets = [bin_dir / "ace_logic.py", bin_dir / "ace.bat", bin_dir / "etcs.exe"]
        else:
            targets = [bin_dir / "ace", bin_dir / "etcs"]
            
        for t in targets:
            if t.exists() or t.is_symlink(): t.unlink()

        if system != "Windows": self._scrub_env_unix("ACE_ROOT")

        # The deps marker describes the MACHINE, not this tree -- but it is
        # only meaningful while a tree exists to build. Dropped here so a
        # later re-install re-probes rather than trusting a pass recorded
        # against a toolchain that may have changed in between. The registry
        # itself is deliberately left alone.
        marker = self._deps_marker()
        if marker.exists():
            marker.unlink()
            print(f"[*] Cleared dependency marker (registry preserved).")

        print(f"\n[!] Deleting ACE_ROOT: {root_dir}")
        self._delayed_self_destruct(root_dir, system)
        sys.exit(0)

    def setup(self, module_name, platform_model="default"):
        """Scaffold a module, register it in the global registry, and hook the ETCS symlink.

        If called from inside the ETCS modules directory, scaffolds directly
        without creating a circular symlink. Otherwise creates a symlink in
        the modules registry pointing to the external source location.
        """
        try: module_name = self._validate_module_name(module_name)
        except ValueError as e: print(f"Error: {e}"); return

        current_workdir = Path.cwd()

        if len(current_workdir.parts) < 3:
            print(f"Error: CWD too shallow ({current_workdir}). ACE modules must be 2+ levels deep.")
            return

        modules_dir = self.ace_root / "modules"
        modules_dir.mkdir(exist_ok=True)

        target_dir = current_workdir / module_name
        source_mod_link = modules_dir / module_name

        in_modules_dir = current_workdir.resolve() == modules_dir.resolve()

        if source_mod_link.exists() and not in_modules_dir:
            print("[-] Error: Module already exists in registry."); return

        localFolders = [module_name]
        if not platform_model == "OS":
            localFolders.append("Linux")
            localFolders.append("Win")
        else:
            localFolders.append("OS")
        
        # Scaffold the module directory structure
        for sub in localFolders:
            (target_dir / sub).mkdir(parents=True, exist_ok=True)

        (target_dir / f"{module_name}.h").write_text(
            f"#ifndef {module_name.upper()}_H__\n"
            f"#define {module_name.upper()}_H__\n\n"
            f"\n#define ETCS_DLL_EXPORTS"
            f"\n#include \"../../core_defs.h\""
            f"\n#include \"../../ontology.h\""
            f"\n#include \"Contract_{module_name}.h\""
            f"\n\n// Make sure to create your tag types exported functions here, with one of: "
            f"\n//  - DEFINE_WORK_FUNC_TYPED(Type, FuncName, (Type, VarName),(Type, VarName), ...)"
            f"\n//  - DEFINE_WORK_FUNC(Type, FuncName)"
            f"\n//  - DEFINE_STREAM_FUNC_PRODUCE(Type, FuncName)"
            f"\n//  - DEFINE_STREAM_FUNC_CONSUME(Type, FuncName)"
            f"\n"
            f"#endif\n"
        )
        (target_dir / f"{module_name}.cc").write_text(
            f"#include \"{module_name}.h\"\n"
            f"\n\nETCS_MODULE_EXPORT_MAIN({module_name}, \"\") // define your tags in this string separated list"
            f"\n// Make sure to create your tag types exported functions in the {module_name}.h included above, with one of: "
            f"\n//  - DEFINE_WORK_FUNC_TYPED(Type, FuncName, (Type, VarName),(Type, VarName), ...)"
            f"\n//  - DEFINE_WORK_FUNC(Type, FuncName)"
            f"\n//  - DEFINE_STREAM_FUNC_PRODUCE(Type, FuncName)"
            f"\n//  - DEFINE_STREAM_FUNC_CONSUME(Type, FuncName)"
            f"\n\n// Then declare your tag type here with an action map decleration, use either: "
            f"\n//  - ETCS_TAG_BLOCK_HYBRID(tag_name, (WorkFunc1, WorkFunc2, ...), (StreamFunc1, StreamFunc2, ...))"
            f"\n//  - ETCS_TAG_BLOCK_BASIC(tag_name, WorkFunc1, WorkFunc2, ...)"
            f"\n// Depending on if you have stream functions on this type or not. Up to you to pick!"
            f"\n// Even wrongly mapped stream functions technically load, they just don't interface via default format"
            f"\n// Also remember, Tag must be a type! You can typedef your types in the Contract_{module_name}.h header for cross platform use."
            f"\n// (Which you probably want if your using this system!)"
        )

        if platform_model == "OS":
            platform_logic = (
                f"#elif defined(_WIN32) || defined(__linux__)\n"
                f"    #define {module_name.upper()}_CONTRACT__\n"
                f"    #include \"OS/OS{module_name}Type.h\"\n"
                f"    typedef OS{module_name}Type {module_name}Type;\n"
            )
            print("[*] Defined OS setup")
        else:
            platform_logic = (
                f"#elif defined(_WIN32)\n"
                f"    #define {module_name.upper()}_CONTRACT__\n"
                f"    #include \"Win/Win{module_name}Type.h\"\n"
                f"    typedef Win{module_name}Type {module_name}Type;\n"
                f"\n"
                f"#elif defined(__linux__)\n"
                f"    #define {module_name.upper()}_CONTRACT__\n"
                f"    #include \"Linux/Lin{module_name}Type.h\"\n"
                f"    typedef Lin{module_name}Type {module_name}Type;\n"
            )

        contract_header_content = (
            f"#ifndef {module_name.upper()}_CONTRACT__\n"
            f"\n"
            f"#if defined(__EMSCRIPTEN__)\n"
            f"    //#define {module_name.upper()}_CONTRACT__\n"
            f"    //#include \"Web/WASM{module_name}Type.h\"\n"
            f"    //typedef WASM{module_name}Type {module_name}Type;\n"
            f"    // We don't support WASM globally yet... \n"
            f"\n"
            f"{platform_logic}"
            f"\n"
            f"#else\n"
            f"    #warning \"{module_name}_Contract: Platform not detected. Check preprocessor definitions.\"\n"
            f"    #error \"Unsupported platform\"\n"
            f"#endif\n\n"
            f"\n// Please typedef your modules types here! Define them for each platform in the blocks above!"
            f"\n// Once you define your types, make sure to export them in {module_name}.cc by adding to both the:"
            f"\n//   - ETCS_MODULE_EXPORT_MAIN({module_name}, \"\") <==== this string list, space separated declaring all tags"
            f"\n//   - And you must add either a ETCS_TAG_BLOCK_HYBRID or ETCS_TAG_BLOCK_BASIC block mapping the tag to your functions."
            f"\n\n// Beware! You must pass causal exhaustion for every OS path to be verified and sellable on the marketplace."
            f"\n"
            f"\n// auto generated hashes of headers:"
            f"\n#include \"../../ETCS.h\""
            f"\n#include \"module_hashes.h\""
            f"\n\n#endif // {module_name.upper()}_CONTRACT__\n"
        )

        (target_dir / f"Template_Contract_{module_name}.h").write_text(contract_header_content)
        self._run_root_make("generate_hashes")
        
        template_files = {
            "module.Makefile": "Makefile",
            "exports.map": "exports.map"
        }
        for src_name, dest_name in template_files.items():
            template_path = modules_dir / src_name
            if template_path.exists():
                shutil.copy(template_path, target_dir / dest_name)
            else:
                print(f"[!] Warning: Template {src_name} not found in {modules_dir}")

        if in_modules_dir:
            # Native module — no symlink, no registry entry
            print(f"[+] Module '{module_name}' scaffolded directly in modules directory.")
            print(f"[*] No symlink created — master Makefile will discover it automatically.")
            print(f"[*] Not added to global registry — native modules are tree-local.")
        else:
            # External module — symlink + registry entry
            etcs_link = current_workdir / "ETCS"
            try:
                if etcs_link.is_symlink(): etcs_link.unlink()
                os.symlink(self.ace_root, etcs_link, target_is_directory=True)
                os.symlink(target_dir, source_mod_link, target_is_directory=True)
                self._registry_add(module_name, target_dir)
                print(f"[+] Module '{module_name}' initialized at {target_dir}")
                print(f"[+] Registered symlink: {source_mod_link} -> {target_dir}")
                print(f"[+] Added to global registry: {self._get_registry_dir() / module_name}")
            except Exception as e:
                print(f"[-] Error during setup: {e}")

    def remove(self, module_name):
        """Delete a single external module, remove its symlink, and remove it from the global registry."""
        try: module_name = self._validate_module_name(module_name)
        except ValueError as e: print(f"Error: {e}"); return

        registry_link = self.ace_root / "modules" / module_name
        if not registry_link.is_symlink():
            print(f"[-] Error: '{module_name}' not found as an external module in this tree.")
            print(f"[*] Native modules are managed by the tree, not ace.")
            return

        target_dir = registry_link.resolve()
        etcs_link = target_dir.parent / "ETCS"

        if not self._confirm(f"Obliterate module '{module_name}' at {target_dir}?", False): return

        if etcs_link.is_symlink(): etcs_link.unlink()

        if target_dir.exists():
            if len(target_dir.parts) <= 3:
                print(f"  [!] Safety triggered: refusing to delete shallow path {target_dir}")
                return
            shutil.rmtree(target_dir)

        registry_link.unlink()
        self._registry_remove(module_name)
        print(f"[+] Module '{module_name}' obliterated.")
        print(f"[+] Removed from global registry.")

    def stage(self, module_name, destination):
        """Copy module artifacts to a destination. Supports 'qvm:qube-name' syntax."""
        module_name = self._validate_module_name(module_name)
        source = (self.ace_root / "modules" / module_name).resolve()

        if not source.exists():
            print(f"[-] Staging failed: module '{module_name}' not found."); return

        if destination.startswith("qvm:") and platform.system() != "Windows":
            target_qube = destination.split(":", 1)[1]
            print(f"[*] Copying '{module_name}' to qube: {target_qube}...")
            subprocess.run(["qvm-copy-to-vm", target_qube, str(source)], check=True)
        else:
            print(f"[*] Staging '{module_name}' to {destination}...")
            shutil.copytree(source, destination, dirs_exist_ok=True)
        print("[+] Staging complete.")

    def list_modules(self):
        """Alias for the unified module view. `ace list` and bare `ace abi`
        now show the same thing -- kept as a synonym so existing habits and
        scripts don't break. See _list_all_modules for the real work."""
        self._list_all_modules()

    def _list_modules_legacy_unused(self):
        modules_dir = self.ace_root / "modules"
        if not modules_dir.exists():
            print("[-] No modules directory found."); return

        external = sorted([m for m in modules_dir.iterdir() if m.is_symlink()])
        native = sorted([
            m for m in modules_dir.iterdir()
            if not m.is_symlink() and m.is_dir() and (m / "Makefile").exists()
        ])

        total = len(external) + len(native)
        if total == 0:
            print("  (no modules registered)"); return

        print(f"\n--- ACE Modules ({total}) ---")

        if native:
            print(f"  {DIM}native (in-tree):{RESET}")
            self._print_name_grid([item.name for item in native],
                                  per_row=4, indent="    ", color=YELLOW)

        if external:
            print(f"  {DIM}external (symlinked):{RESET}")
            self._print_name_grid([item.name for item in external],
                                  per_row=4, indent="    ", color=CYAN)
            # The grid drops the symlink targets, so list them under it in the
            # same order -- an external module without its target is just a name.
            for item in external:
                print(f"      {DIM}{item.name} -> {item.resolve()}{RESET}")

        registry_dir = self._get_registry_dir()
        print(f"\n  {DIM}global registry: {registry_dir}{RESET}")

