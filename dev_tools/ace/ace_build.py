"""ace build subsystem.

Part of the `ace` dev tool, split by causal boundary: this file owns the
build surface and nothing else. Mixed into AceManager in ace_install.py --
all methods are `self`-bound and may call across subsystems through the one
assembled object, but each subsystem's *definition* lives in exactly one file.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import subprocess
import re

from .ace_common import (CYAN, YELLOW, GREEN, RED, RESET, DIM)


# THE VARIABLES A CALLER MAY SET ON AN ace make LINE.
#
# An allowlist rather than a filter, because the failure it prevents is not a
# typo -- every one of these becomes a make variable in a recipe, so an
# unbounded set is an unbounded way to rewrite the build. Names only; the VALUES
# are still checked for shell metacharacters above.
#
# THE ETCS_WEB_* KNOBS ARE HERE BECAUSE THE GENERATED MAKEFILE ADVERTISES THEM.
# Each one is documented in loaders/Makefile as a `make FILE=etcs EMSCRIPTEN=1
# ETCS_WEB_x=...` line -- the whole point of `?=` on those defaults is that a
# developer can try a variant without regenerating anything. Refusing them here
# made the documented command fail, which is worse than not documenting it: it
# reads as the override not existing rather than as one layer not knowing about
# it. If a new ETCS_WEB_* default is added to that Makefile, it belongs here in
# the same change.
ACE_MAKE_VARS = frozenset({
    "ACE_ROOT", "VERBOSE", "DEBUG", "ASAN", "TSAN", "LOG_TO_FILE", "EMSCRIPTEN",
    # Web link knobs -- see loaders/Makefile's own comments for each.
    "ETCS_WEB_MEMORY", "ETCS_WEB_POOL", "ETCS_WEB_JSLIBS",
    # Per-loader link additions, kept OUT of LDFLAGS on purpose (see the
    # generated Makefile). This is how --profiling-funcs is passed to keep the
    # name section, which is what makes a wasm trace address resolvable.
    "EXTRA_LINK",
})

class BuildMixin:


    # ================================================================
    # Change detection
    # ================================================================
    #
    # WHY THIS IS ACE'S JOB AND NOT MAKE'S. Every module's own Makefile
    # already tracks its headers correctly, and would happily do nothing on a
    # no-op rebuild -- but the batch target depends on clean_modules, so
    # `ace make modules` deletes every artifact before make can decide
    # anything. The decision has to be made one level up, before the clean.
    #
    # WHAT A MODULE'S FINGERPRINT HAS TO COVER, and the second half is the
    # non-obvious one:
    #
    #   its own sources and headers    -- changing them changes the .so
    #   the GENERATED global hash files -- ontology_hashes.h, libs_hashes.h,
    #                                      core_hashes.h
    #
    # Those three are compiled INTO every module and compared against the
    # loader's copies at load time; a module built against an older set is
    # refused with "built for different epochs" rather than misbehaving. So
    # narrowing this to "the ontology families this module actually uses"
    # would be wrong in a way that looks right: the module would skip, load,
    # and abort, because the check is over the whole set and not over the part
    # it uses. Hashing the generated files also covers the headers they are
    # derived from, so an edit anywhere in ontology/, libs/ or core/ correctly
    # invalidates every module at once.
    #
    # FLAGS ARE IN IT TOO. A DEBUG or ASAN build is a different artifact from
    # the same sources, and the module Makefiles already encode that in their
    # own build stamp; this is the same fact, one level up.

    _FINGERPRINT_NAME = ".ace_build_fingerprint"

    # Generated headers first: they are what the loader compares. The umbrella
    # headers are listed because they are includable directly and are not
    # covered by any of the generated files.
    _GLOBAL_FINGERPRINT_FILES = (
        "ontology_hashes.h",
        "libs_hashes.h",
        "core_hashes.h",
        "ontology.h",
        "libs.h",
        "core_defs.h",
    )

    _SOURCE_SUFFIXES = {".h", ".hpp", ".hh", ".inc", ".c", ".cc", ".cpp", ".cxx"}

    # Never part of a module's identity: build outputs, dependency files, and
    # the per-module hash header, which is DERIVED from the very files being
    # hashed and would make every fingerprint depend on the last build.
    _FINGERPRINT_EXCLUDED_NAMES = {"module_hashes.h"}

    @staticmethod
    def _hash_files(paths):
        h = hashlib.sha256()
        for path in paths:
            # The NAME goes in as well as the bytes: a file renamed is a
            # change, and hashing contents alone would miss it.
            h.update(str(path).encode("utf-8", "replace"))
            h.update(b"\0")
            try:
                with open(path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 16), b""):
                        h.update(chunk)
            except OSError:
                h.update(b"<unreadable>")
            h.update(b"\0")
        return h.hexdigest()

    def _global_fingerprint(self):
        """The generated hash headers plus the umbrella includes.

        A miss here invalidates EVERY module, which is correct: these are what
        the loader compares against, and a module out of step with them cannot
        load at all."""
        return self._hash_files(
            self.ace_root / name for name in self._GLOBAL_FINGERPRINT_FILES)

    def _module_source_files(self, mod):
        """Every source and header the module owns, FETCHED trees excluded.

        A dependency pinned by commit and fetched into the module directory is
        a function of its pin, not of anything a developer edits -- walking it
        would hash tens of thousands of files to learn nothing. The pin itself
        lives in the Makefile, which IS hashed. The test below is for git
        metadata, so it catches exactly those.

        A tree vendored by COMMITTING IT (source.type "vendored" in the
        manifest -- LayoutProvider/clay) has no .git and is therefore hashed
        like our own code. That is the right answer rather than an oversight:
        those bytes are in our history, an upgrade is a commit here, and a
        rebuild is exactly what should follow one. It costs a single SHA-256
        over a few hundred KB."""
        root = self.ace_root / "modules" / mod
        if not root.is_dir():
            return []
        out = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(part.startswith(".") for part in path.relative_to(root).parts):
                continue
            # A vendored checkout is anything with its own git metadata.
            if any((root.joinpath(*path.relative_to(root).parts[:i + 1]) / ".git").exists()
                   for i in range(len(path.relative_to(root).parts) - 1)):
                continue
            if path.name in self._FINGERPRINT_EXCLUDED_NAMES:
                continue
            if path.name == "Makefile" or path.suffix in self._SOURCE_SUFFIXES:
                out.append(path)
        return out

    def _module_fingerprint(self, mod, extras):
        """The full record for a module: what it is built FROM, and HOW.

        Kept as separate components rather than one digest so a skip decision
        can say WHICH half moved -- "the ontology changed" and "you edited this
        module" are different answers and a developer wants to know which one
        they are looking at."""
        manifest = self._manifest_dir() / f"{mod}.json"
        return {
            "global": self._global_fingerprint(),
            "local": self._hash_files(self._module_source_files(mod)),
            "manifest": self._hash_files([manifest]) if manifest.is_file() else "",
            "flags": " ".join(sorted(extras)),
        }

    def _fingerprint_path(self, mod):
        return self.ace_root / "modules" / mod / self._FINGERPRINT_NAME

    def _module_build_reason(self, mod, extras):
        """None if the module is up to date, else why it is not.

        The .so has to EXIST as well as match: a fingerprint describes what a
        build would produce, and a fingerprint with no artifact beside it is a
        record of a build somebody deleted."""
        so = self._bin_dir() / f"{mod}.{self._artifact_ext(extras)}"
        if not so.is_file():
            return "no built artifact in bin/"

        path = self._fingerprint_path(mod)
        if not path.is_file():
            return "never built through this check"
        try:
            with open(path, "r", encoding="utf-8") as fh:
                old = json.load(fh)
        except (OSError, ValueError):
            return "unreadable build record"

        new = self._module_fingerprint(mod, extras)
        if old.get("global") != new["global"]:
            return "ontology / libs / core hashes changed"
        if old.get("manifest") != new["manifest"]:
            return "manifest changed"
        if old.get("local") != new["local"]:
            return "module sources changed"
        if old.get("flags") != new["flags"]:
            return "build flags changed"
        return None

    def _record_module_fingerprint(self, mod, extras):
        """Written only after a build that SUCCEEDED and left an artifact.

        BOTH CONDITIONS, and the first one is the one that bites. A failed
        build leaves the PREVIOUS .so sitting in bin/, so "an artifact exists"
        is true for a module that did not build at all -- record on that alone
        and the next run skips a module whose binary predates the change,
        which surfaces later as the loader refusing it for a hash mismatch.
        Found exactly that way, by an interrupted batch.

        So the caller passes make's own verdict, and a failure leaves no
        record at all: the module is rebuilt next time, which is the only safe
        default when the truth is unknown."""
        so = self._bin_dir() / f"{mod}.{self._artifact_ext(extras)}"
        if not so.is_file():
            return
        try:
            with open(self._fingerprint_path(mod), "w", encoding="utf-8") as fh:
                json.dump(self._module_fingerprint(mod, extras), fh, indent=1)
        except OSError as e:
            print(f"    {DIM}(could not record build fingerprint for {mod}: {e}){RESET}")

    def _lib_ext(self):
        system = platform.system()
        if system == "Windows":
            return "dll"
        if system == "Darwin":
            return "dylib"
        return "so"

    def _is_web_build(self, extras):
        return any(a.startswith("EMSCRIPTEN=") for a in (extras or []))

    def _artifact_ext(self, extras):
        """The suffix this module's artifact wears under these flags: a web
        build produces a .wasm side module, and every existence check and
        fingerprint record must ask for the file these flags produce."""
        return "wasm" if self._is_web_build(extras) else self._lib_ext()

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

            # -U as well as -D: both are preprocessor flags and both belong in
            # EXTRADEFINES. -U is what makes an always-on define (see
            # LOADER_DEFAULT_DEFINES) something a caller can still turn off,
            # instead of a wall.
            if arg.startswith("-D") or arg.startswith("-U"):
                defines.append(arg)
                continue

            if '=' in arg:
                key, val = arg.split('=', 1)
                if key not in ACE_MAKE_VARS:
                    raise ValueError(
                        f"Disallowed variable: {key} "
                        f"(allowed: {', '.join(sorted(ACE_MAKE_VARS))})")
                if key == 'EMSCRIPTEN' and val != '1':
                    raise ValueError("EMSCRIPTEN=1 is the only supported form")
                validated.append(arg)
            else:
                if arg not in self.allowed_make_targets | self.root_make_targets:
                    raise ValueError(f"Disallowed make target: {arg}")
                validated.append(arg)

        if defines:
            validated.append(f"EXTRADEFINES={' '.join(defines)}")

        return validated

    # EVERY LOADER BUILD IS THE INTERACTIVE ONE, unless a caller undefines it.
    #
    # -DETCS_REPL_SHELL selects the top-level loop and nothing else
    # (loaders/etcs.cc): with it the binary takes ShellProvider's terminal and
    # prompts, without it the same source drains and exits. Both write
    # bin/etcs(.js), so whichever build ran last wins and the artifact carries
    # no mark of which one it is.
    #
    # It used to be per-spelling -- ON for `ace make loader <n>`, OFF when you
    # named `etcs` explicitly, and absent from the PLURAL `loaders` that
    # `ace make all` and `ace wasm make all` both route through. So "build
    # everything" emitted the draining variant, and a page whose terminal
    # expects a navigator loaded its modules and exited 0 with nothing on the
    # console to say why. On the web there is no daemon to be: nothing calls
    # into a wasm loader that has already returned from main.
    #
    # The escape is an ordinary compiler flag rather than a mode: pass
    # -UETCS_REPL_SHELL for the draining loader. Spelled that way because it
    # says what it does to the build, and _validate_make_args now carries -U
    # through for the same reason.
    LOADER_DEFAULT_DEFINES = ("-DETCS_REPL_SHELL",)

    @staticmethod
    def _loader_extras(user_args):
        """The loader's own defines in front of the caller's.

        In front, not appended, so an explicit -UETCS_REPL_SHELL wins by being
        later; and skipped entirely when the caller already spelled either half
        of the pair, so EXTRADEFINES never carries both.
        """
        def macro(a):
            return a[2:].split("=", 1)[0]

        spoken = {macro(a) for a in user_args if a.startswith(("-D", "-U"))}
        defaults = [d for d in BuildMixin.LOADER_DEFAULT_DEFINES
                    if macro(d) not in spoken]
        return defaults + list(user_args)

    def _announce_loader_variant(self, loader_name, extras):
        """Say WHICH etcs this build produced, because the file cannot."""
        if loader_name != "etcs":
            return
        art = "bin/etcs.js" if self._is_web_build(extras) else "bin/etcs"
        joined = " ".join(str(a) for a in (extras or []))
        if "-UETCS_REPL_SHELL" in joined:
            print(f"{YELLOW}[=] {art} is the DAEMON loader -- no REPL shell. "
                  f"A script runs and then drains.{RESET}")
        else:
            print(f"{GREEN}[=] {art} is the INTERACTIVE loader "
                  f"(-DETCS_REPL_SHELL).{RESET}")

    def _drop_stale_artifact(self, name, extras, kind="module"):
        """Remove what a FAILED build left behind in bin/.

        A build that fails leaves the PREVIOUS artifact sitting there, and
        nothing downstream can tell the difference: serving bin/wasm/ then ships
        a binary that does not match the source it was built from -- and now that
        a page mounts that directory rather than holding its own copy, one stale
        file reaches every page at once. That is the worst shape a build failure can take --
        it does not look like one. Staging a stale module beside fresh ones is
        also how a manifest-epoch mismatch appears at runtime instead of here.

        Removed rather than renamed: the next thing to touch it should fail
        loudly for a missing file, which every consumer already handles, rather
        than succeed against something older than the tree.
        """
        web = self._is_web_build(extras)
        # bin/wasm/ on the web path, bin/ otherwise -- the same split the copy
        # targets make (ARTIFACT_DIR in loaders/Makefile, WASM_DIR in ETCS's
        # Makefile). Looking in bin/ for a web artifact would find nothing and
        # leave the stale one in bin/wasm/ exactly where a page mounts it, which
        # is the failure this whole function exists to prevent.
        bin_dir = self.ace_root / "bin" / "wasm" if web else self.ace_root / "bin"
        if not bin_dir.is_dir():
            return
        rel = bin_dir.name if not web else "bin/wasm"
        if kind == "loader":
            names = [f"{name}.js", f"{name}.wasm"] if web else [name]
        else:
            names = [f"{name}.{self._artifact_ext(extras)}"]
        for n in names:
            art = bin_dir / n
            if art.exists():
                try:
                    art.unlink()
                    print(f"{YELLOW}[!] removed stale {rel}/{n} -- the build that "
                          f"should have replaced it failed.{RESET}")
                except OSError as ex:
                    print(f"{RED}[-] could not remove stale {rel}/{n}: {ex}{RESET}")

    # ================================================================
    # Parallelism
    # ================================================================

    @staticmethod
    def _host_cores():
        """Cores this process may actually run on, not cores the box has.

        sched_getaffinity is the honest number inside a container or under
        taskset, where cpu_count reports the host and a build sized by it
        oversubscribes a two-core cgroup by an order of magnitude.
        """
        try:
            return max(1, len(os.sched_getaffinity(0)))
        except (AttributeError, OSError):
            return max(1, os.cpu_count() or 1)

    # What one link of this tree actually costs, measured rather than guessed:
    # peak RSS during a wasm side-module link was ~1.19 GB and the MAIN_MODULE
    # loader link ~0.93 GB (sampled once a second across both). wasm-ld and
    # wasm-opt are the whole of it -- the node the toolchain also runs peaked at
    # 16 MB, so this is not a JS heap problem and raising node's would fix
    # nothing. Rounded UP, because the number is a peak on one tree and the
    # thing it is protecting against is the OOM killer.
    _LINK_MEM_BUDGET_MB = 1400

    def _host_avail_mb(self):
        """MemAvailable, or None where it cannot be read.

        MemAvailable and not MemTotal: what matters is what can be handed out
        now without reclaim, and on a developer's machine the difference is an
        editor, a browser and a language server.
        """
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) // 1024
        except (OSError, ValueError, IndexError):
            pass
        return None

    def _job_count(self):
        """How many things ace builds at once -- the one number, for both halves.

        BOUNDED BY MEMORY AS WELL AS BY CORES, and the memory bound is the one
        that bites. A core count is how many compilers can make progress; it
        says nothing about how many can fit. Eight cores against 8 GB of RAM and
        a link that peaks over a gigabyte is not a fast build, it is a build that
        ends as the OOM killer's problem -- and a link killed that way leaves the
        PREVIOUS artifact in place, so the next run serves a stale binary and the
        failure resurfaces as a runtime bug in a build that looked like it
        worked. That is the expensive part: not the lost build, the lost
        afternoon afterwards.

        ACE_JOBS OVERRIDES BOTH, unchanged: an explicit number is somebody who
        knows their machine, and inferring over a stated decision is the one
        thing this must not do. ACE_JOBS=1 is still how you read an error log
        that several compilers would otherwise be interleaving.
        """
        override = os.environ.get("ACE_JOBS", "").strip()
        if override:
            try:
                return max(1, int(override))
            except ValueError:
                print(f"{YELLOW}[!] ACE_JOBS={override!r} is not a number -- "
                      f"using the inferred count.{RESET}")

        cores = self._host_cores()
        avail = self._host_avail_mb()
        if avail is None:
            return cores
        fits = max(1, avail // self._LINK_MEM_BUDGET_MB)
        if fits < cores:
            print(f"{DIM}    jobs: {fits} (memory-bound -- {avail} MB available, "
                  f"~{self._LINK_MEM_BUDGET_MB} MB per link; {cores} cores. "
                  f"ACE_JOBS overrides){RESET}")
        return min(cores, fits)

    def _job_args(self, extra_args=()):
        """make's -j, or nothing when someone has already decided.

        THREE WAYS TO NOT DECIDE HERE, in the order they are checked:

          a -j/--jobs already in extra_args   the caller asked for a number;
                                              a second -j silently wins and
                                              would override it
          -j already in MAKEFLAGS             ace was invoked from inside a
                                              make, which hands its job SERVER
                                              down through MAKEFLAGS -- adding
                                              our own here detaches this
                                              sub-make from it and the two
                                              pools multiply
          one job                             ACE_JOBS=1; -j1 and no flag are
                                              the same build, and the flag would
                                              only claim a decision was made

        Bare `-j` is deliberately not used: unbounded make on a linker-heavy
        tree is how a build ends as the OOM killer's problem instead of the
        compiler's.
        """
        for a in extra_args:
            if a == "-j" or a.startswith("-j") or a.startswith("--jobs"):
                return []
        if any(f == "-j" or f.startswith("-j") or f.startswith("--jobs")
               for f in os.environ.get("MAKEFLAGS", "").split()):
            return []
        n = self._job_count()
        return [] if n <= 1 else [f"-j{n}"]

    def _build_modules_concurrently(self, mods, extras):
        """Build these modules at once, bounded by the cores available.

        Returns [(module, ok)] in the order given.

        OUTPUT IS HELD AND PRINTED WHOLE, one block per module. Streaming it
        would interleave several compilers' diagnostics exactly when it matters,
        which is when one of them is the error -- and a wall of warnings whose
        module cannot be told apart is the same as no output. The blocks are
        printed in the order asked for rather than the order they finish, so two
        runs of the same build produce logs that can be diffed.
        """
        if not mods:
            return []
        workers = max(1, min(self._job_count(), len(mods)))
        if workers > 1:
            print(f"{DIM}    parallel: {workers} modules at a time{RESET}")

        def one(mod):
            cmd = ["make", "-C", str(self.ace_root), f"ACE_ROOT={self.ace_root}",
                   f"module_{mod}"] + list(extras)
            try:
                p = subprocess.run(cmd, capture_output=True, text=True)
            except OSError as ex:
                return False, f"[-] could not run make: {ex}\n"
            return p.returncode == 0, (p.stdout or "") + (p.stderr or "")

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [(mod, pool.submit(one, mod)) for mod in mods]
            out = []
            for mod, fut in futures:
                ok, log = fut.result()
                mark = f"{CYAN}{mod}{RESET}" if ok else f"{RED}{mod}{RESET}"
                print(f"\n--- {mark} ---")
                if log.strip():
                    print(log.rstrip())
                out.append((mod, ok))
        return out

    def _run_root_make(self, target, extra_args=None, keep_going=False):
        """Run a target against the master Makefile at ace_root with extra flags.

        keep_going passes make's -k, so one module's failure does not abort its
        siblings -- their builds are unrelated to the failed one.

        -j GOES ON THE ROOT INVOCATION AND NOWHERE ELSE. Every sub-make below
        this one inherits the job server through MAKEFLAGS, so one flag here
        parallelises modules against each other and loaders against each other
        without any Makefile passing anything on by hand -- and without the two
        levels each opening a pool of their own.
        """
        if extra_args is None:
            extra_args = []

        master_makefile = self.ace_root / "Makefile"
        if not master_makefile.exists():
            print(f"[-] Error: No master Makefile found at {self.ace_root}")
            return False

        print(f"[*] Routing to master Makefile for target: {target}")
        make_cmd = ["make", "-C", str(self.ace_root), f"ACE_ROOT={self.ace_root}", target]
        jobs = self._job_args(extra_args)
        if jobs:
            print(f"{DIM}    parallel: make {jobs[0]}{RESET}")
        make_cmd.extend(jobs)
        if keep_going:
            make_cmd.append("-k")
        make_cmd.extend(extra_args)

        try:
            subprocess.run(make_cmd, check=True)
            return True
        except subprocess.CalledProcessError as e:
            # Under keep_going a non-zero exit just means some target failed; the
            # modules that built are still valid, so this is a warning, not a stop.
            print(f"[-] Build error: {e}")
            return False

    def make(self, args):
        """Run make with auto-healing ETCS links."""
        if not args:
            print("[-] Error: No make target specified.")
            print("    Usage: ace make { all | modules | loaders | clean | clean modules | clean loaders | module <n> | clean module <n> | loader <n> | clean loader <n> }")
            return

        # --force is ACE's own flag, not make's, so it comes out of the
        # argument list before anything tries to validate it as a make target.
        # Accepted anywhere in the line because that is where people type it.
        force = False
        filtered = []
        for a in args:
            if a in ("--force", "-B"):
                force = True
                continue
            filtered.append(a)
        args = filtered
        if not args:
            print("[-] Error: No make target specified.")
            return 1

        if self._is_web_build(args):
            if not shutil.which("em++"):
                print(f"{RED}[-] EMSCRIPTEN build requested but em++ is not on PATH.{RESET}")
                print(f"{DIM}    source <emsdk-root>/emsdk_env.sh first{RESET}")
                return 1

        # Once per (distro, arch), then never again -- a marker read, not a
        # probe sweep, on every subsequent build.
        self._deps_first_run()

        # ONCE, HERE, AND THEN DECLARED DONE.
        #
        # module_%, modules and loaders all name generate_hashes as a
        # prerequisite, so the pass used to run again for every one of them --
        # an openssl invocation per header in ontology/, libs/ and core/, times
        # the number of modules. Harmless while the modules were built in
        # series; a correctness problem the moment they are not, because N
        # processes then rewrite the same three headers while N compiles read
        # them. ACE_HASHES_READY (see the master Makefile's HASH_PREREQ) is how
        # the phase says it has happened, and it goes in the environment so that
        # every make below inherits it without a flag being threaded through.
        if self._run_root_make("generate_hashes"):
            os.environ["ACE_HASHES_READY"] = "1"
        try:
            if args[0] == "loader":
                if len(args) >= 2:
                    loader_name = args[1]
                    user_args = args[2:]
                else:
                    loader_name = "etcs"
                    user_args = []
                # Unconditional now, including when 'etcs' is named explicitly:
                # see LOADER_DEFAULT_DEFINES for what that spelling used to mean
                # and why -UETCS_REPL_SHELL replaced it.
                extras = self._validate_make_args(self._loader_extras(user_args))
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
                    return 1
                # Same contract as modules: the shared loaders/Makefile is a
                # generated artifact, regenerated when missing, never
                # overwritten when present.
                self.ensure_loaders_makefile()
                print(f"[*] Building loader: {loader_name}")
                # FILE= narrows the sources to one, but `all` still links that
                # loader AND etcs, so -j has two things to overlap here.
                make_cmd = [
                    "make",
                    "-C", str(loaders_dir),
                    f"ACE_ROOT={self.ace_root}",
                    f"FILE={loader_name}",
                ] + self._job_args(extras) + extras
                try:
                    subprocess.run(make_cmd, check=True)
                except subprocess.CalledProcessError as e:
                    print(f"[-] Loader build error: {e}")
                    self._drop_stale_artifact(loader_name, extras, "loader")
                    return 1
                if self._is_web_build(extras):
                    # THE MAIN LINK IS WHERE THIS CAN BE ANSWERED, which is why the
                    # check runs here and not after a module build. A side module
                    # emits no JavaScript, so the JS library behind a `-sUSE_*`
                    # flag arrives only if the LOADER link asked for it -- and with
                    # -sERROR_ON_UNDEFINED_SYMBOLS=0 (mandatory for MAIN_MODULE) a
                    # symbol nobody defines is not rejected, it becomes a stub that
                    # throws the first time something calls it. Silent at link
                    # time, silent at load time, and fatal in a browser with a
                    # stack that names neither the symbol nor the module. See
                    # ace_wasm. Reported, not fatal: the link itself succeeded, and
                    # an unreached stub is a real (if fragile) state to ship.
                    self.wasm_link([], quiet_when_clean=True)
                self._announce_loader_variant(loader_name, extras)
                return 0

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
                    return 1
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
                # Deliberately NOT removed here: loaders/Makefile is shared by
                # every loader, so cleaning ONE loader must not delete the file
                # the others build from. `ace make clean loaders` does remove it.
                return

            if len(args) >= 2 and args[0] == "module":
                raw_names, raw_flags = self._split_names_and_flags(args[1:])
                if not raw_names:
                    print("[-] Error: `make module` needs at least one module name.")
                    return 1
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

                # ...then build them, with a pre/post ABI diff around the batch
                # so the per-module reminder still pops regardless of batch size.
                #
                # THE THREE STEPS ARE PHASES, not a per-module cycle, because the
                # builds in the middle now run concurrently. pre-build still means
                # "before this build" and post-build still means "the drift this
                # build produced" -- the pairing is over the batch instead of over
                # one module, which is what it already meant for a batch of one.
                failed = []
                # Generated Makefiles are build artifacts and gitignored, so a
                # fresh clone has none. Regenerating a MISSING one here is what
                # makes that a non-event; an existing one is never touched, so a
                # module that predates its manifest keeps building until someone
                # migrates it deliberately.
                for mod in mods:
                    self.ensure_makefile(mod)
                # nm cannot read wasm: ELF-side ABI introspection is skipped for
                # web builds rather than run to failure.
                web = self._is_web_build(extras)
                for mod in mods:
                    if web:
                        print(f"[*] {mod}: web build -- ABI introspection skipped.")
                    else:
                        print(f"[*] Current ABI interface for {mod} (pre-build):")
                        self.introspect_and_record(mod, announce=True)

                results = self._build_modules_concurrently(mods, extras)

                for mod, ok in results:
                    if not web:
                        print(f"[*] ABI interface for {mod} (post-build):")
                        self.introspect_and_record(mod, announce=True)
                    # A named module is ALWAYS built -- asking for it by name
                    # is the request -- but the record is written only if the
                    # build worked, so a later `ace make modules` knows this
                    # one is current and leaves it alone.
                    if ok:
                        self._record_module_fingerprint(mod, extras)
                    else:
                        failed.append(mod)
                        self._drop_stale_artifact(mod, extras, "module")
                if failed:
                    print(f"{RED}[-] {len(failed)} module(s) failed: "
                          f"{', '.join(failed)}{RESET}")
                    return 1
                return 0

            if len(args) >= 3 and args[0] == "clean" and args[1] == "module":
                raw_names, raw_flags = self._split_names_and_flags(args[2:])
                if not raw_names:
                    print("[-] Error: `make clean module` needs a module name.")
                    return 1
                mods = [self._validate_module_name(n) for n in raw_names]
                extras = self._validate_make_args(raw_flags)
                if len(mods) > 1:
                    print(f"[*] Cleaning {len(mods)} modules:")
                    self._print_name_grid(mods, per_row=4, indent="    ",
                                          color=CYAN)
                    print()
                for mod in mods:
                    # make clean FIRST -- it runs out of the very Makefile
                    # removed next, and a generated Makefile is itself a build
                    # artifact now, so leaving it behind means `clean` did not
                    # clean. The next build regenerates it.
                    self._run_root_make(f"clean_module_{mod}", extra_args=extras)
                    self.clean_makefile(mod)
                return

            if len(args) >= 2 and args[0] == "clean" and args[1] in ("modules", "loaders"):
                extras = self._validate_make_args(args[2:])
                self._run_root_make(f"clean_{args[1]}", extra_args=extras)
                if args[1] == "loaders":
                    self.clean_loaders_makefile()
                else:
                    for mod in sorted(set(self._all_manifests())
                                      | set(self._defaulted_modules())):
                        self.clean_makefile(mod)
                return

            if args[0] in self.root_make_targets:
                extras = self._validate_make_args(args[1:])
                # The loader half of a batch gets the loader's own defines; the
                # module half must NOT, since a module compiled with
                # -DETCS_REPL_SHELL is a different fingerprint for no reason.
                loader_extras = self._validate_make_args(
                    self._loader_extras(args[1:]))
                batch = args[0] in ("all", "modules")

                # Regenerate BEFORE make is invoked, not during.
                #
                # The master Makefile discovers modules with
                #   MODULE_SUBDIRS := $(wildcard $(MODULES_DIR)/*/Makefile)
                # which make expands while PARSING, before any recipe runs. A
                # missing generated Makefile is therefore not a module that
                # fails to build -- it is a module that is not there at all,
                # and `ace make modules` prints "Building Modules" followed by
                # nothing and exits 0.
                #
                # That went unnoticed because only the SINGULAR paths
                # (`module <n>`, `loader <n>`) ensured their Makefile; the
                # batch ones never did. Harmless until clean started removing
                # them, at which point the two changes combined into a build
                # that silently did nothing.
                if args[0] in ("all", "modules"):
                    for mod in sorted(set(self._all_manifests())
                                      | set(self._defaulted_modules())):
                        self.ensure_makefile(mod)
                if args[0] in ("all", "loaders"):
                    self.ensure_loaders_makefile()

                if batch:
                    self._announce_full_tagset()

                # THE MODULE HALF IS DRIVEN PER MODULE, not through the
                # `modules` target, and that is what makes skipping possible
                # at all: that target depends on clean_modules, so it deletes
                # every artifact before make can decide anything. Driving
                # module_<name> one at a time keeps make's own incremental
                # decisions intact underneath and lets a whole module be
                # skipped above them.
                failed = []
                if args[0] in ("all", "modules"):
                    mods = sorted(set(self._all_manifests())
                                  | set(self._defaulted_modules()))
                    build, skipped = [], []
                    for mod in mods:
                        reason = None if force else self._module_build_reason(mod, extras)
                        if force:
                            reason = "forced"
                        if reason is None:
                            skipped.append(mod)
                        else:
                            build.append((mod, reason))

                    if skipped:
                        print(f"[=] Unchanged, not rebuilt ({len(skipped)}):")
                        self._print_name_grid(skipped, per_row=4, indent="    ",
                                              color=DIM)
                    if build:
                        print(f"[*] Building {len(build)} module(s):")
                        for mod, reason in build:
                            print(f"    {CYAN}{mod}{RESET}  {DIM}({reason}){RESET}")
                    elif not skipped:
                        print("[!] No modules found to build.")
                    print()

                    # ONE MODULE PER CORE, not one module at a time.
                    #
                    # A module is a single translation unit, so make's -j has
                    # nothing to overlap INSIDE one; all of the concurrency this
                    # tree has is BETWEEN modules, and this loop is where it was
                    # being thrown away -- every module waited for the previous
                    # module's link. The skip logic above is untouched: only the
                    # modules that were already going to build are what run here.
                    #
                    # Each module's dependencies live under its own directory and
                    # its artifacts are its own name, so the makes do not collide;
                    # the one thing they SHARE is the generated hash headers, and
                    # those are written once before this point (ACE_HASHES_READY).
                    results = self._build_modules_concurrently(
                        [mod for mod, _ in build], extras)
                    for mod, ok in results:
                        if ok:
                            self._record_module_fingerprint(mod, extras)
                        else:
                            # No record at all -- the next run rebuilds it, and
                            # the OLD artifact goes with it. Leaving it was the
                            # quiet half of this failure: anything that keyed
                            # off the artifact's existence called the module
                            # current, and staging bin/ shipped a binary older
                            # than its source.
                            failed.append(mod)
                            self._drop_stale_artifact(mod, extras, "module")
                    if failed:
                        print(f"{RED}[-] {len(failed)} module(s) failed and were not "
                              f"recorded; they will rebuild next run:{RESET}")
                        self._print_name_grid(failed, per_row=4, indent="    ",
                                              color=RED)

                    # Unconditional: a module that was skipped still has to be
                    # in bin/, and one that failed should not take its
                    # siblings' artifacts with it.
                    self._run_root_make("copy_modules", extra_args=extras)
                    for module, so in self._all_module_sos():
                        self.introspect_and_record(module, so_path=so, announce=False)

                if args[0] in ("all", "loaders"):
                    # Loaders are NOT skipped. A loader carries the same
                    # generated hash headers every module does and is the side
                    # that every module is compared AGAINST at load time, so a
                    # stale loader does not merely miss a change -- it refuses
                    # every module built after it. It is also one link.
                    if not self._run_root_make("loaders", extra_args=loader_extras):
                        failed.append("loaders")
                        self._drop_stale_artifact("etcs", loader_extras, "loader")
                    else:
                        self._announce_loader_variant("etcs", loader_extras)
                if failed:
                    return 1
                return 0

        except ValueError as e:
            print(f"[-] Flag validation error: {e}")
            return 1

        current_dir = Path.cwd()

        if not (current_dir / "Makefile").exists():
            print("[-] Error: No Makefile found in current directory.")
            return 1

        etcs_link = current_dir.parent / "ETCS"
        if not etcs_link.is_symlink() or etcs_link.resolve() != self.ace_root:
            if etcs_link.exists() or etcs_link.is_symlink():
                etcs_link.unlink()
            try:
                os.symlink(self.ace_root, etcs_link, target_is_directory=True)
            except PermissionError:
                print("[!] Warning: Could not update ETCS link.")