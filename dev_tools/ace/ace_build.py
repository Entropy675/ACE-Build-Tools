"""ace build subsystem.

Part of the `ace` dev tool, split by causal boundary: this file owns the
build surface and nothing else. Mixed into AceManager in ace_install.py --
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


class BuildMixin:

    def _validate_module_name(self, name):
        """Clean module name: keep alphanumerics and underscores for cross-platform safety."""
        if not isinstance(name, str):
            raise ValueError("Module name must be a string")
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '', name.strip().strip('/'))
        if not clean_name:
            raise ValueError(f"Module name '{name}' contains no valid characters")
        if len(clean_name) > 64:
            raise ValueError("Sanitized module name too long (max 64 chars)")
        return clean_name

    def _validate_make_args(self, args):
        validated = []
        defines = []

        for arg in args:
            if any(char in arg for char in [';', '&', '|', '$', '`', '\n', '\r']):
                raise ValueError(f"Illegal characters: {arg}")

            if arg.startswith("-D"):
                defines.append(arg)
                continue

            if '=' in arg:
                key, _ = arg.split('=', 1)
                if key not in ['ACE_ROOT', 'VERBOSE', 'DEBUG', 'ASAN', 'LOG_TO_FILE']:
                    raise ValueError(f"Disallowed variable: {key}")
                validated.append(arg)
            else:
                if arg not in self.allowed_make_targets | self.root_make_targets:
                    raise ValueError(f"Disallowed make target: {arg}")
                validated.append(arg)

        if defines:
            validated.append(f"EXTRADEFINES={' '.join(defines)}")

        return validated

    def _run_root_make(self, target, extra_args=None, keep_going=False):
        """Run a target against the master Makefile at ace_root with extra flags.

        keep_going passes make's -k, so one module's failure does not abort its
        siblings -- their builds are unrelated to the failed one.
        """
        if extra_args is None:
            extra_args = []

        master_makefile = self.ace_root / "Makefile"
        if not master_makefile.exists():
            print(f"[-] Error: No master Makefile found at {self.ace_root}")
            return

        print(f"[*] Routing to master Makefile for target: {target}")
        make_cmd = ["make", "-C", str(self.ace_root), f"ACE_ROOT={self.ace_root}", target]
        if keep_going:
            make_cmd.append("-k")
        make_cmd.extend(extra_args)

        try:
            subprocess.run(make_cmd, check=True)
        except subprocess.CalledProcessError as e:
            # Under keep_going a non-zero exit just means some target failed; the
            # modules that built are still valid, so this is a warning, not a stop.
            print(f"[-] Build error: {e}")

    def make(self, args):
        """Run make with auto-healing ETCS links."""
        if not args:
            print("[-] Error: No make target specified.")
            print("    Usage: ace make { all | modules | loaders | clean | clean modules | clean loaders | module <n> | clean module <n> | loader <n> | clean loader <n> }")
            return

        # Once per (distro, arch), then never again -- a marker read, not a
        # probe sweep, on every subsequent build.
        self._deps_first_run()

        self._run_root_make("generate_hashes")
        try:
            if args[0] == "loader":
                if len(args) >= 2:
                    loader_name = args[1]
                    user_args = args[2:]
                else:
                    loader_name = "etcs"
                    user_args = []
                # A loader is only ever built standalone in order to run it with the
                # shell, so -DETCS_REPL_SHELL is always on; user -D flags stack on top.
                extras = self._validate_make_args(["-DETCS_REPL_SHELL"] + user_args)
                print("With extras: ")
                for i in extras:
                    print(i)
                if loader_name.startswith("Run_"):
                    loader_name = loader_name[4:]
                if loader_name.endswith(".cc"):
                    loader_name = loader_name[:-3]
                loader_name = self._validate_module_name(loader_name)
                loaders_dir = self.ace_root / "loaders"
                if not loaders_dir.exists():
                    print(f"[-] Error: No loaders directory found at {loaders_dir}")
                    return
                print(f"[*] Building loader: {loader_name}")
                make_cmd = [
                    "make",
                    "-C", str(loaders_dir),
                    f"ACE_ROOT={self.ace_root}",
                    f"FILE={loader_name}",
                ] + extras
                try:
                    subprocess.run(make_cmd, check=True)
                except subprocess.CalledProcessError as e:
                    print(f"[-] Loader build error: {e}")
                return

            if len(args) >= 2 and args[0] == "clean" and args[1] == "loader":
                loader_name = args[2] if len(args) >= 3 else "etcs"
                if loader_name.startswith("Run_"):
                    loader_name = loader_name[4:]
                if loader_name.endswith(".cc"):
                    loader_name = loader_name[:-3]
                loader_name = self._validate_module_name(loader_name)
                loaders_dir = self.ace_root / "loaders"
                if not loaders_dir.exists():
                    print(f"[-] Error: No loaders directory found at {loaders_dir}")
                    return
                print(f"[*] Cleaning loader: {loader_name}")
                make_cmd = [
                    "make",
                    "-C", str(loaders_dir),
                    f"ACE_ROOT={self.ace_root}",
                    f"FILE={loader_name}",
                    "clean",
                ]
                try:
                    subprocess.run(make_cmd, check=True)
                except subprocess.CalledProcessError as e:
                    print(f"[-] Loader clean error: {e}")
                return

            if len(args) >= 2 and args[0] == "module":
                raw_names, raw_flags = self._split_names_and_flags(args[1:])
                if not raw_names:
                    print("[-] Error: `make module` needs at least one module name.")
                    return
                mods = [self._validate_module_name(n) for n in raw_names]
                # Flags validate ONCE and apply to every named module.
                extras = self._validate_make_args(raw_flags)

                # Grid the set being built as an overview...
                if len(mods) > 1:
                    print(f"[*] Building {len(mods)} modules:")
                    self._print_name_grid(mods, per_row=4, indent="    ",
                                          color=CYAN)
                    if extras:
                        print(f"    {DIM}flags applied to all: "
                              f"{' '.join(extras)}{RESET}")
                    print()

                # ...then build each, with its own pre/post ABI diff so the
                # per-module reminder still pops regardless of batch size.
                for mod in mods:
                    print(f"[*] Current ABI interface for {mod} (pre-build):")
                    self.introspect_and_record(mod, announce=True)
                    self._run_root_make(f"module_{mod}", extra_args=extras)
                    self.introspect_and_record(mod, announce=False)
                return

            if len(args) >= 3 and args[0] == "clean" and args[1] == "module":
                raw_names, raw_flags = self._split_names_and_flags(args[2:])
                if not raw_names:
                    print("[-] Error: `make clean module` needs a module name.")
                    return
                mods = [self._validate_module_name(n) for n in raw_names]
                extras = self._validate_make_args(raw_flags)
                if len(mods) > 1:
                    print(f"[*] Cleaning {len(mods)} modules:")
                    self._print_name_grid(mods, per_row=4, indent="    ",
                                          color=CYAN)
                    print()
                for mod in mods:
                    self._run_root_make(f"clean_module_{mod}", extra_args=extras)
                return

            if len(args) >= 2 and args[0] == "clean" and args[1] in ("modules", "loaders"):
                extras = self._validate_make_args(args[2:])
                self._run_root_make(f"clean_{args[1]}", extra_args=extras)
                return

            if args[0] in self.root_make_targets:
                extras = self._validate_make_args(args[1:])
                batch = args[0] in ("all", "modules")
                if batch:
                    self._announce_full_tagset()
                # Keep going so one module's failure doesn't take down its siblings...
                self._run_root_make(args[0], extra_args=extras, keep_going=batch)
                if batch:
                    # ...then copy unconditionally, so every module that DID build
                    # lands in ./bin instead of vanishing with the aborted run.
                    self._run_root_make("copy_modules", extra_args=extras)
                    for module, so in self._all_module_sos():
                        self.introspect_and_record(module, so_path=so, announce=False)
                return

        except ValueError as e:
            print(f"[-] Flag validation error: {e}")
            return

        current_dir = Path.cwd()

        if not (current_dir / "Makefile").exists():
            print("[-] Error: No Makefile found in current directory.")
            return

        etcs_link = current_dir.parent / "ETCS"
        if not etcs_link.is_symlink() or etcs_link.resolve() != self.ace_root:
            if etcs_link.exists() or etcs_link.is_symlink():
                etcs_link.unlink()
            try:
                os.symlink(self.ace_root, etcs_link, target_is_directory=True)
            except PermissionError:
                print("[!] Warning: Could not update ETCS link.")

        try:
            validated = self._validate_make_args(args)
            subprocess.run(["make", f"ACE_ROOT={self.ace_root}"] + validated, check=True)
        except (ValueError, subprocess.CalledProcessError) as e:
            print(f"[-] Build error: {e}")
