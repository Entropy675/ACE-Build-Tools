"""ace manifest subsystem.

Part of the `ace` dev tool, split by causal boundary: this file owns the
manifest surface and nothing else. Mixed into AceManager in ace_install.py --
all methods are `self`-bound and may call across subsystems through the one
assembled object, but each subsystem's *definition* lives in exactly one file.

WHAT A MANIFEST IS

A module declares what it NEEDS (system packages, vendored dependencies),
what it MAKES (a loadable module), and WHERE THAT GOES. This file turns that
declaration into a Makefile. The Makefile is a build artifact: it is
gitignored, regenerated whenever it is missing, and hand-editing it is not a
supported workflow -- the edit is lost the next time it regenerates.

WHY GENERATE RATHER THAN HAND-MAINTAIN

Four hand-written module Makefiles in this ecosystem had four different
answers to the same questions, and the disagreements were all silent:

  - DatabaseProvider's DEPFILE rule lacked an order-only dependency on its
    sqlite bootstrap, so `-include $(DEPFILE)` ran the -MM preprocess before
    sqlite3.h existed. The build printed a fatal error and then succeeded on
    the retry, which is the worst possible way for a bug to present.
  - Only NetworkProvider stamped its vendored artifacts with the build
    architecture. The other two relink stale objects after a tree moves
    between machines.
  - DatabaseProvider is a shared-layout module (it has OS/) that inherited
    the per-platform template, so its header glob resolves to Linux/*.h,
    matches nothing, and its actual implementation headers have never been
    covered by the manifest hashes at all.
  - Three modules put vendored archives on the link line before the
    translation unit that needs them. gold does not rescan an archive it has
    already passed, so that only works by the accident of --whole-archive or
    of nothing yet needing a late symbol.

Every one of those is emitted correctly by construction here, for every
module, whether or not anyone remembered.

WHY THE SCHEMA IS CLOSED

Module submissions are accepted as manifests, not as Makefiles. A raw
Makefile is arbitrary code that no reviewer can bound. A manifest names a
pinned ref, an enumerated build system, and a fixed set of paths -- which is
still code execution at build time, but code execution a human can read the
whole of before saying yes. `build.system` is therefore a closed enum with no
shell escape: a dependency that needs something else is rejected, because the
escape hatch IS the thing this format exists to stop accepting.
"""
from pathlib import Path
import hashlib
import json
import re
import subprocess

from .ace_common import (CYAN, YELLOW, GREEN, RED, RESET, DIM)


SCHEMA_VERSION = 1

# Build systems we know how to drive. Deliberately closed -- see module docstring.
BUILD_SYSTEMS = {"none", "cmake", "autotools", "make"}

# Refuse to build against an unpinned dependency. The placeholder is spelled
# out so a half-written manifest fails loudly at generation rather than
# quietly cloning whatever upstream HEAD happens to be that morning.
UNPINNED = {"TODO-PIN", "", "HEAD", "master", "main"}

# Flags every ETCS module is compiled with. A manifest can ADD to these but
# cannot remove them by omission: they are the ABI contract with the runtime,
# and a module that opts out of -fvisibility=hidden silently exports its
# internals past the version script.
BASE_CXXFLAGS = [
    "-std={std}", "-fvisibility=hidden", "-Wall", "-fPIC", "-Wextra", "-O2",
]

# Loader baseline. -DETCS_LOADER is what DynamicLoader's preprocessor
# branches read; ETCS_MODULE_NAME is "ROOT" because a loader is the root
# arena's own translation unit, not a module.
BASE_LOADER_CXXFLAGS = [
    "-std={std}", "-fvisibility=hidden", "-fpermissive", "-Wall",
    "-Wextra", "-O2", "-I../..", "-pipe", "-fno-plt",
    "-DETCS_LOADER", r'-DETCS_MODULE_NAME=\"ROOT\"',
]

# The line every generated Makefile opens with, and the ONLY thing that
# authorises this tool to delete one. A hand-written Makefile -- a module not
# yet migrated, or one someone deliberately kept -- has no such line and is
# never touched. Emitted from here rather than written out at each emitter so
# the marker and the check cannot drift apart into a delete that matches
# nothing, or worse, one that matches too much.
GENERATED_MARKER = "# GENERATED FILE -- do not edit."

# Every platform-implementation directory a module can carry. The HASH scope
# spans all of them that exist; the COMPILE scope is only the active one.
# See _emit_makefile's header-discovery block for why those differ.
PLATFORM_DIRS = ["Linux", "Win", "Web", "OS"]

GLOBAL_HEADERS = [
    "../../ontology.h", "../../ontology_hashes.h",
    "../../libs.h", "../../libs_hashes.h", "../../core_defs.h",
]


def _sanitize(text):
    """Filename-safe form of a git ref, for use in a marker filename."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", text)


def _var(name):
    """Make variable name for a dependency."""
    return "DEP_" + re.sub(r"[^A-Za-z0-9]", "_", name).upper()


def _abi_tag(abi_defines):
    """Short, stable tag for a set of ABI-affecting defines.

    Folded into the build-stamp and dependency-marker filenames so that
    EDITING abi_defines invalidates everything built against the old set.

    This is not tidiness. MBEDTLS_THREADING_C adds mutex members to
    mbedTLS context structs: add it to a manifest without this tag and
    make sees a correctly-rebuilt library sitting beside a module still
    compiled against the old struct layout, decides nothing is out of
    date, and produces a binary that links, loads, and corrupts memory.
    Changing the tag changes the filenames, so the stale halves cannot
    survive.
    """
    if not abi_defines:
        return ""
    joined = " ".join(sorted(abi_defines))
    return "_" + hashlib.sha256(joined.encode()).hexdigest()[:8]


class ManifestError(Exception):
    """Raised for a manifest that cannot be trusted to describe a build."""


class ManifestMixin:

    # ------------------------------------------------------------------
    # location
    # ------------------------------------------------------------------

    def _manifest_dir(self):
        """Manifests live with the TOOL, not with the tree.

        `ace make module X` must know how to build X before X's directory has
        anything in it worth reading, and the same manifest has to be usable
        when the module is a symlink into somebody's home directory. Keying
        off tool_root gives one known location regardless of where the module
        source physically sits.
        """
        return self.tool_root / "manifests"

    def _manifest_path(self, module):
        return self._manifest_dir() / f"{module}.json"

    def _default_manifest_path(self):
        """The manifest a module with nothing to declare resolves to.

        A module with no vendored dependencies and no unusual flags has
        nothing module-specific to say, and making every such module carry a
        near-identical file is how those four hand-written Makefiles drifted
        apart in the first place -- copies with no reason to differ, that
        differed anyway. ForumWebsiteProvider and ChessProvider are both this
        case.

        Mirrors loaders/default.loader.json, which already works this way.
        """
        return self._manifest_dir() / "default.json"

    def _module_dir(self, module):
        return self.ace_root / "modules" / module

    def has_manifest(self, module):
        """True if this module can be generated -- via its own manifest or
        the default. `ace make module X` reaches the build path on either."""
        return (self._manifest_path(module).is_file()
                or self._default_manifest_path().is_file())

    def uses_default(self, module):
        return (not self._manifest_path(module).is_file()
                and self._default_manifest_path().is_file())

    # ------------------------------------------------------------------
    # removal
    # ------------------------------------------------------------------

    def _is_generated(self, path):
        """Did THIS tool write that Makefile?

        The one question that decides whether it may be deleted. A module not
        yet migrated, or one whose Makefile someone deliberately keeps by
        hand, carries no marker and survives every clean -- which matters
        because `clean` is exactly the command people run without reading it
        first, and a generator that eats hand-written files once is a
        generator nobody trusts again.
        """
        try:
            with path.open("r", errors="replace") as f:
                return GENERATED_MARKER in f.read(512)
        except OSError:
            return False

    def clean_makefile(self, module, quiet=False):
        """Delete one module's GENERATED Makefile. Returns True if removed."""
        mk = self._module_dir(module) / "Makefile"
        if not mk.is_file():
            return False
        if not self._is_generated(mk):
            if not quiet:
                print(f"  {YELLOW}[!]{RESET} {module}/Makefile is hand-written "
                      f"-- left alone.")
            return False
        mk.unlink()
        if not quiet:
            print(f"  {GREEN}[-]{RESET} removed {module}/Makefile")
        return True

    def clean_loaders_makefile(self, quiet=False):
        mk = self.ace_root / "loaders" / "Makefile"
        if not mk.is_file():
            return False
        if not self._is_generated(mk):
            if not quiet:
                print(f"  {YELLOW}[!]{RESET} loaders/Makefile is hand-written "
                      f"-- left alone.")
            return False
        mk.unlink()
        if not quiet:
            print(f"  {GREEN}[-]{RESET} removed loaders/Makefile")
        return True

    def clean_all_makefiles(self, quiet=False):
        """Every generated Makefile in the tree -- own-manifest modules,
        defaulted modules, and the shared loaders one."""
        n = 0
        for mod in sorted(set(self._all_manifests()) | set(self._defaulted_modules())):
            if self.clean_makefile(mod, quiet=quiet):
                n += 1
        if self.clean_loaders_makefile(quiet=quiet):
            n += 1
        return n

    # ------------------------------------------------------------------
    # loading and validation
    # ------------------------------------------------------------------

    def load_manifest(self, module, resolve_pins=False, silent=False):
        """Read and validate one manifest. Raises ManifestError.

        resolve_pins offers to fill in an unpinned ref rather than rejecting
        outright -- see _resolve_unpinned. Off for `check`, which reports
        state and must not change it; on for the generate and build paths,
        where the user is present and a pin is the one thing standing between
        them and a build.
        """
        path = self._manifest_path(module)
        defaulted = False
        if not path.is_file():
            path = self._default_manifest_path()
            defaulted = True
            if not path.is_file():
                raise ManifestError(
                    f"no manifest at {self._manifest_path(module)}, and no "
                    f"{path.name} to fall back to")
        try:
            m = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            raise ManifestError(f"{path.name} is not valid JSON: {e}")

        if defaulted:
            # The default cannot name itself, so the requested module supplies
            # the name. Recorded so the generated header says which file it
            # came from -- a Makefile that points at default.json when the
            # reader expects <Module>.json is the kind of small confusion that
            # costs a real debugging session.
            m.setdefault("module", {})["name"] = module
            m["_defaulted"] = True

        if resolve_pins:
            self._resolve_unpinned(m, module, path, silent)
        self._validate_manifest(m, module, path)
        return m

    # ------------------------------------------------------------------
    # pinning
    # ------------------------------------------------------------------

    def _ask(self, message, silent=False):
        """_confirm, but survives a pipe. A non-interactive run has nobody to
        answer, and input() there raises rather than returning a default --
        which would turn 'unpinned dependency' into an opaque traceback in
        CI."""
        if silent:
            return True
        try:
            return self._confirm(message, False)
        except (EOFError, KeyboardInterrupt):
            print()
            return False

    def _git(self, *args, cwd=None):
        """Run git, returning stripped stdout or None. Never raises."""
        try:
            r = subprocess.run(["git", *args], cwd=str(cwd) if cwd else None,
                               capture_output=True, text=True, timeout=30)
            return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None
        except (OSError, subprocess.SubprocessError):
            return None

    def _discover_ref(self, module, dep):
        """What this dependency is ACTUALLY at right now.

        The clone already sitting in the module directory is the best possible
        answer: it is, by construction, the thing that currently builds. A tag
        is preferred over a sha because it survives a force-push and reads as
        an intention rather than a coordinate.

        Falls back to the remote's HEAD, which is a real pin (a sha) but only
        pins 'whatever upstream was at the moment you asked' -- reported as
        such so nobody mistakes it for a considered choice.
        """
        dep_dir = self._module_dir(module) / dep["name"]
        if (dep_dir / ".git").exists():
            tag = self._git("describe", "--exact-match", "--tags", "HEAD", cwd=dep_dir)
            if tag:
                return tag, f"tag checked out in {module}/{dep['name']}"
            sha = self._git("rev-parse", "HEAD", cwd=dep_dir)
            if sha:
                return sha, f"commit checked out in {module}/{dep['name']}"

        url = dep.get("source", {}).get("url")
        if url:
            out = self._git("ls-remote", url, "HEAD")
            if out:
                return out.split()[0], "remote HEAD as of right now (not a considered pin)"
        return None, None

    def _resolve_unpinned(self, m, module, path, silent=False):
        """Offer to pin every unpinned dependency, and write the answers back.

        Rejecting on the spot is correct but unhelpful: the information needed
        to fix it is sitting in the module's own working tree, and making the
        user go read it out by hand just to paste it back is a chore the tool
        can do. Declining still leaves validation to reject the manifest, so
        the guarantee is unchanged -- nothing builds unpinned either way.

        Never writes to default.json. It is shared by every module that has
        nothing of its own to declare, so a pin recorded there would apply to
        all of them -- and it carries no vendored dependencies to pin in the
        first place.
        """
        if path == self._default_manifest_path():
            return False
        changed = False
        for dep in m.get("requires", {}).get("vendor", []):
            src = dep.get("source", {})
            if src.get("type") != "git" or src.get("ref") not in UNPINNED:
                continue

            print(f"\n  {YELLOW}[!]{RESET} {module}: dependency "
                  f"{CYAN}{dep['name']}{RESET} is unpinned "
                  f"{DIM}(ref: {src.get('ref')!r}){RESET}")

            ref, origin = self._discover_ref(module, dep)
            if not ref:
                print(f"      {DIM}No clone in the tree and the remote did not answer; "
                      f"pin it by hand.{RESET}")
                continue

            print(f"      Found {GREEN}{ref}{RESET} {DIM}-- {origin}{RESET}")
            if not self._ask(f"      Pin {dep['name']} to this?", silent):
                print(f"      {DIM}Left unpinned.{RESET}")
                continue

            src["ref"] = ref
            changed = True
            print(f"      {GREEN}[+]{RESET} pinned.")

        if changed:
            path.write_text(json.dumps(m, indent=2) + "\n")
            print(f"  {GREEN}[+]{RESET} updated {path.name}\n")
        return changed

    def _validate_manifest(self, m, module, path):
        ver = m.get("schema_version")
        if ver != SCHEMA_VERSION:
            # Refuse rather than guess: a manifest from a newer schema may
            # rely on a field this generator would silently ignore, and
            # silently ignoring a build instruction is how you ship a module
            # built differently from how its author described it.
            raise ManifestError(
                f"{path.name} declares schema_version {ver!r}, this ace knows {SCHEMA_VERSION}")

        name = m.get("module", {}).get("name")
        if name != module:
            raise ManifestError(
                f"{path.name} declares module.name {name!r} but is filed as {module!r}")

        for dep in m.get("requires", {}).get("vendor", []):
            dname = dep.get("name", "<unnamed>")
            src = dep.get("source", {})
            stype = src.get("type")

            if stype == "git":
                ref = src.get("ref")
                if ref in UNPINNED:
                    raise ManifestError(
                        f"dependency {dname!r} has ref {ref!r}. Pin it to a tag or a full "
                        f"sha -- an unpinned dependency builds against whatever upstream "
                        f"moved to overnight, and cannot be reviewed for submission.\n"
                        f"      Your existing clone knows the answer:\n"
                        f"      git -C modules/{module}/{dname} describe --tags --always")
            elif stype == "vendored":
                if not src.get("path"):
                    raise ManifestError(f"dependency {dname!r} is vendored but declares no path")
            else:
                raise ManifestError(f"dependency {dname!r} has unknown source.type {stype!r}")

            build = dep.get("build")
            if build is not None:
                sysname = build.get("system")
                if sysname not in BUILD_SYSTEMS:
                    raise ManifestError(
                        f"dependency {dname!r} wants build system {sysname!r}. "
                        f"Supported: {', '.join(sorted(BUILD_SYSTEMS))}. There is no shell "
                        f"escape by design -- an arbitrary command is the raw Makefile this "
                        f"format exists to replace.")

        # Every -l should have something that installs it. A warning rather
        # than an error: a module may legitimately link something supplied by
        # the base system, and failing the build over that would be worse
        # than saying so.
        claimed = set()
        for pkgs in m.get("requires", {}).get("system", {}).values():
            for p in pkgs:
                claimed.update(p.get("provides_link", []))
        builtin = {"dl", "pthread", "m", "rt", "stdc++", "c"}
        for plat, blk in m.get("build", {}).items():
            for lib in blk.get("system_libs", []):
                if lib in claimed or lib in builtin or lib.endswith("32"):
                    continue
                print(f"  {YELLOW}[!]{RESET} {module} [{plat}] links -l{lib}, "
                      f"but no declared package provides it.")

    # ------------------------------------------------------------------
    # emission
    # ------------------------------------------------------------------

    def _emit_makefile(self, m):
        """Render a manifest as a Makefile. Pure -- touches no filesystem."""
        mod = m["module"]
        name = mod["name"]
        std = mod.get("std", "c++17")
        platforms = mod.get("platforms", ["Linux"])
        layout = mod.get("impl_layout", "per_platform")
        produces = m.get("produces", {})
        exports = produces.get("exports", "exports.map")
        vendor = m.get("requires", {}).get("vendor", [])
        build = m.get("build", {})
        common = build.get("common", {})

        # Collected up front because the build stamp's NAME depends on them,
        # and the stamp is emitted above the dependency loop that declares
        # them. Deduplicated, order-preserving: two dependencies may
        # legitimately require the same define.
        abi_defines = []
        for dep in vendor:
            for d in dep.get("abi_defines", []):
                if d not in abi_defines:
                    abi_defines.append(d)
        abi_tag = _abi_tag(abi_defines)

        L = []
        w = L.append

        w("# " + "=" * 68)
        w(GENERATED_MARKER)
        w("#")
        src_file = "default.json" if m.get("_defaulted") else f"{name}.json"
        w(f"#   source:      <ace tool>/manifests/{src_file}")
        if m.get("_defaulted"):
            w(f"#                ({name} declares nothing of its own -- no")
            w("#                 vendored dependencies, no unusual flags)")
        w(f"#   regenerate:  ace manifest generate {name}")
        w("#")
        w("# Edits here are lost the next time this file is regenerated, which")
        w("# happens automatically whenever it is missing. Change the manifest.")
        w("# " + "=" * 68)
        w("")
        w(f"TARGET_BASE_NAME := {name}")
        w(f"GLOBAL_HEADERS := {' '.join(GLOBAL_HEADERS)}")
        w("SRC_MODULE := $(TARGET_BASE_NAME).cc")
        w("HASH_HEADER := module_hashes.h")
        w("")
        w("UNAME_S := $(shell uname -s)")
        w("ARCH    := $(shell uname -m)")
        w("NPROC   := $(shell nproc)")
        w("CXX := g++")
        w("CC  := gcc")
        w("")
        w("# Debug info: make DEBUG=1. OFF by default.")
        w("#")
        w("# -g roughly doubles a module's on-disk size, and the hand-written")
        w("# Makefiles disagreed about it -- NetworkProvider and DatabaseProvider")
        w("# carried it, ChessProvider did not. Making it a mode rather than a")
        w("# baseline is what lets all four agree without picking a winner.")
        w("#")
        w("# A sanitizer build turns it on regardless: a sanitizer report without")
        w("# line numbers is a list of hex addresses, which is the situation")
        w("# ASAN/TSAN exist to get you out of.")
        w("DEBUGFLAGS :=")
        w("DBG_SUFFIX :=")
        w("ifeq ($(DEBUG),1)")
        w("    DEBUGFLAGS := -g")
        w("    DBG_SUFFIX := _dbg")
        w("endif")
        w("")
        w("# " + "-" * 66)
        w("# Sanitizers: make ASAN=1 / make TSAN=1.")
        w("#")
        w("# Mutually exclusive -- they instrument the same code paths and cannot")
        w("# coexist in one binary.")
        w("#")
        w("# The module and whatever loader dlopens it MUST be built the same way.")
        w("# They share one address space, and a sanitizer runtime that sees only")
        w("# half of it reports nonsense.")
        w("#")
        w("# Vendored dependencies are NOT rebuilt for ASan: it interposes malloc")
        w("# and free process-wide, so allocation faults inside an uninstrumented")
        w("# library are still caught -- that is exactly how mbedTLS's PSA")
        w("# double-free was found. TSan is different: it only sees races in code")
        w("# it instrumented, so TSAN=1 rebuilds them.")
        w("# " + "-" * 66)
        w("SANITIZE   :=")
        w("SAN_SUFFIX :=")
        w("ifeq ($(ASAN),1)")
        w("ifeq ($(TSAN),1)")
        w("    $(error ASAN=1 and TSAN=1 are mutually exclusive)")
        w("endif")
        w("    SANITIZE   := -fsanitize=address -fno-omit-frame-pointer")
        w("    SAN_SUFFIX := _asan")
        w("endif")
        w("ifeq ($(TSAN),1)")
        w("    SANITIZE   := -fsanitize=thread -fno-omit-frame-pointer")
        w("    SAN_SUFFIX := _tsan")
        w("endif")
        w("")
        w("# Vendored dependencies follow only the TSan half, per the note above:")
        w("# rebuilding them costs minutes, and for ASan it buys only overflow")
        w("# detection INSIDE the dependency -- allocation faults there are caught")
        w("# either way.")
        w("DEP_SANITIZE   :=")
        w("DEP_SAN_SUFFIX :=")
        w("ifeq ($(TSAN),1)")
        w("    DEP_SANITIZE   := -fsanitize=thread -fno-omit-frame-pointer")
        w("    DEP_SAN_SUFFIX := _tsan")
        w("endif")
        w("")
        w("# Symbols are not optional under a sanitizer -- see the DEBUG note.")
        w("ifneq ($(SANITIZE),)")
        w("    DEBUGFLAGS := -g")
        w("endif")
        w("")
        w("# Build stamp -- architecture, sanitizer, and ABI-define set.")
        w("#")
        w("# A REAL prerequisite of the final target, not order-only: switching")
        w("# any of the three must force a relink, and make has no other way to")
        w("# notice that CXXFLAGS changed. Mixing instrumented and uninstrumented")
        w("# objects in one .so links cleanly and then misbehaves at runtime,")
        w("# which is precisely what this stamp exists to make impossible. The")
        w("# architecture half matters for the same reason it always did: a tree")
        w("# carried to another machine would otherwise relink objects built for")
        w("# the architecture it came from.")
        w(f"BUILD_STAMP := .ace_build_$(ARCH)$(DBG_SUFFIX)$(SAN_SUFFIX){abi_tag}")
        w("")

        # ---- per-dependency variables ------------------------------------
        fetch_markers, build_markers, obj_targets = [], [], []
        inline_srcs, link_items, dep_includes = [], [], []
        obj_rules, fetch_rules, build_rules = [], [], []
        clean_paths = []

        for dep in vendor:
            v = _var(dep["name"])
            src = dep["source"]
            prov = dep.get("provides", {})

            if src["type"] == "vendored":
                w(f"{v}_DIR := {src['path']}")
            else:
                w(f"{v}_DIR := {dep['name']}")
            w("")

            # fetch
            if src["type"] == "git":
                marker = f"$({v}_DIR)/.ace_fetched_{_sanitize(src['ref'])}"
                fetch_markers.append(marker)
                fetch_rules.append(self._emit_fetch_rule(v, dep, marker))

            # build
            if dep.get("build"):
                bd = dep["build"].get("build_dir", "build")
                marker = (f"$({v}_DIR)/{bd}/.ace_built_$(ARCH)$(DEP_SAN_SUFFIX)"
                          + _abi_tag(dep.get("abi_defines", [])))
                build_markers.append(marker)
                build_rules.append(
                    self._emit_build_rule(
                        v, dep, marker,
                        fetch_markers[-1] if src["type"] == "git" else None))
                clean_paths.append(f"$({v}_DIR)/{bd}")

            for inc in prov.get("include", []):
                dep_includes.append(f"-I$({v}_DIR)/{inc}" if inc != "." else f"-I$({v}_DIR)")

            sources = prov.get("sources")
            if sources:
                globs = " ".join(f"$(wildcard $({v}_DIR)/{g})" for g in sources.get("include", []))
                expr = globs
                if sources.get("exclude"):
                    ex = " ".join(f"$({v}_DIR)/{e}" for e in sources["exclude"])
                    expr = f"$(filter-out {ex}, {globs})"
                w(f"{v}_SRCS := {expr}")
                if sources.get("cflags"):
                    # Own flags -> own objects. Cannot ride the module's compile
                    # line, which would apply C++ flags to C and the module's
                    # feature defines to a dependency that never asked for them.
                    w(f"{v}_OBJS := $(patsubst $({v}_DIR)/%,.ace_obj/{v}_%,$(basename $({v}_SRCS)))")
                    w(f"{v}_OBJS := $(addsuffix .o,$({v}_OBJS))")
                    obj_targets.append(f"$({v}_OBJS)")
                    # Ordered behind this dependency's own fetch and build:
                    # sqlite's sqlite3.c does not exist until configure has
                    # run, and without this make reports it as a missing
                    # target rather than building it.
                    gate = [mk for mk in (
                        fetch_markers[-1] if src["type"] == "git" else None,
                        build_markers[-1] if dep.get("build") else None,
                    ) if mk]
                    obj_rules.append(self._emit_obj_rule(v, dep, sources, gate))
                else:
                    inline_srcs.append(f"$({v}_SRCS)")
                w("")

            for art in prov.get("link", []):
                path = f"$({v}_DIR)/{art['path']}"
                if art.get("mode") == "whole_archive":
                    link_items.append(f"-Wl,--whole-archive {path} -Wl,--no-whole-archive")
                else:
                    link_items.append(path)

        # ---- flags --------------------------------------------------------
        cxx = [f.format(std=std) for f in BASE_CXXFLAGS]
        cxx.append(r'-DETCS_MODULE_NAME=\"$(TARGET_BASE_NAME)\"')
        cxx += ["-I.", "-I../.."]
        cxx += dep_includes
        # ABI defines, emitted here AND into every dependency's own build (see
        # _emit_build_rule). One field, two places, because that is what
        # correctness requires -- having to remember it in both by hand is how
        # a struct layout ends up disagreeing across a link.
        cxx += [f"-D{d}" for d in abi_defines]
        cxx += [f"-D{d}" for d in common.get("defines", [])]
        cxx += common.get("cxxflags", [])
        cxx += ["-pipe", "-fno-plt", "$(DEBUGFLAGS)", "$(SANITIZE)",
                "$(CUSTOM_CXXFLAGS)"]
        w("CXXFLAGS := " + " \\\n            ".join(cxx))
        w("")

        if layout == "shared":
            w("# Shared implementation layout: one OS/ directory serves every target.")
            w("PLATFORM_DIR := OS")
            w("")

        # ---- platform blocks ---------------------------------------------
        # Web is tested FIRST and the order is load-bearing: under emscripten
        # `uname -s` still reports Linux, so a Linux branch placed above it
        # matches and the whole toolchain override -- em++, SIDE_MODULE -- is
        # silently skipped. The manifest may list platforms in any order.
        ordered = ([p for p in platforms if p == "Web"]
                   + [p for p in platforms if p != "Web"])
        first = True
        for plat in ordered:
            blk = build.get(plat, {})
            cond = {"Linux": "Linux", "Win": "Windows_NT", "Web": "Emscripten"}.get(plat, plat)
            if plat == "Web":
                w(("ifdef EMSCRIPTEN" if first else "else ifdef EMSCRIPTEN"))
            else:
                kw = "ifeq" if first else "else ifeq"
                w(f"{kw} ($(UNAME_S),{cond})")
            first = False

            if layout == "per_platform":
                w(f"    PLATFORM_DIR := {plat}")
            elif layout == "auto":
                # Resolved after the chain -- see the priority block below.
                w(f"    HOST_PLATFORM := {plat}")
            if blk.get("compiler"):
                w(f"    CXX := {blk['compiler']}")
            if blk.get("cxxflags"):
                w(f"    CXXFLAGS += {' '.join(blk['cxxflags'])}")
            if blk.get("defines"):
                w(f"    CXXFLAGS += {' '.join('-D' + d for d in blk['defines'])}")

            ext = ".dll" if plat == "Win" else ".so"
            w(f"    FINAL_TARGET := $(TARGET_BASE_NAME){ext}")

            ld = ["-shared"]
            if plat != "Web":
                ld += ["-fuse-ld=gold", "-Wl,--threads", "-Wl,--thread-count,$(NPROC)"]
            ld += blk.get("ldflags", [])
            if plat == "Linux" and exports:
                # ELF only. On Win the version script is silently ignored,
                # which reads as an exported surface that is not actually
                # enforced -- better to not claim it at all.
                ld.append(f"-Wl,--version-script={exports}")
            w(f"    LDFLAGS := {' '.join(ld)}")
            w(f"    SYSLIBS := {' '.join('-l' + l for l in blk.get('system_libs', []))}")

        w("else")
        w("    $(error Unsupported platform: $(UNAME_S))")
        w("endif")
        w("")
        if layout == "auto":
            w("# Implementation layout: auto.")
            w("#")
            w("# An OS/ directory means one implementation serves every target and")
            w("# wins outright; otherwise the host platform's own directory is used.")
            w("# A module with NO platform directory at all resolves to a name that")
            w("# matches nothing, which is correct -- its headers live beside it.")
            w("#")
            w("# Safe to infer now in a way it was not before: MODULE_HEADERS spans")
            w("# every platform directory regardless (see the hash-scope note), so")
            w("# guessing this wrong can no longer silently empty the attestation.")
            w("# It only decides what gets -I'd and what a rebuild depends on.")
            w("PLATFORM_DIR := $(HOST_PLATFORM)")
            w("ifneq ($(wildcard OS/.),)")
            w("    PLATFORM_DIR := OS")
            w("endif")
            w("")
        w("CXXFLAGS += -I$(PLATFORM_DIR)")
        w("")

        # ---- headers ------------------------------------------------------
        w("# Header discovery. Vendored trees are deliberately NOT globbed here")
        w("# unless their manifest entry sets hash_scope: every upstream commit")
        w("# would otherwise churn this module's ABI attestation for a change no")
        w("# consumer can observe.")
        w("LOCAL_HEADERS := $(wildcard $(TARGET_BASE_NAME)/*.h)")
        w("PLATFORM_LOCAL_HEADERS := $(wildcard $(PLATFORM_DIR)/*.h)")
        scoped = [f"$(wildcard $({_var(d['name'])}_DIR)/*.h)"
                  for d in vendor if d.get("hash_scope")]
        w("")
        w("# Every platform directory this module actually carries, whichever")
        w("# one this build compiles against.")
        w(f"POTENTIAL_DIRS := {' '.join(PLATFORM_DIRS)}")
        w("EXISTING_DIRS  := $(foreach d,$(POTENTIAL_DIRS),$(if $(wildcard $(d)/.),$(d)))")
        w("ALL_PLATFORM_HEADERS := $(foreach d,$(EXISTING_DIRS),$(wildcard $(d)/*.h))")
        w("")
        w("# HASH SCOPE -- every platform's headers, not just the active one.")
        w("#")
        w("# The manifest hash is an attestation about the MODULE, so it must not")
        w("# depend on the machine that produced it. Hashing only $(PLATFORM_DIR)")
        w("# means the same commit attests differently on Linux and on Windows,")
        w("# and `ace abi` reports drift that is really just an OS difference --")
        w("# indistinguishable, at the point you read it, from a genuine contract")
        w("# change. WindowProvider's hand-written Makefile got this right and it")
        w("# was lost when the four modules were unified on the per-platform")
        w("# template; this restores it for all of them.")
        w(f"MODULE_HEADERS := $(sort $(LOCAL_HEADERS) $(ALL_PLATFORM_HEADERS) $(TARGET_BASE_NAME).h"
          + ((" " + " ".join(scoped)) if scoped else "") + ")")
        w("")
        w("# COMPILE SCOPE -- only the platform being built, since that is what a")
        w("# rebuild should actually depend on. Editing Win/ must not relink a")
        w("# Linux build; it must still change the hash above.")
        w("COMPILE_HEADERS := $(sort $(LOCAL_HEADERS) $(PLATFORM_LOCAL_HEADERS) $(TARGET_BASE_NAME).h)")
        w("MODULE_DEPS := $(SRC_MODULE) $(COMPILE_HEADERS) $(GLOBAL_HEADERS)"
          + ((" " + " ".join(inline_srcs)) if inline_srcs else ""))
        w("")

        w(".PHONY: all clean")
        w("all: $(FINAL_TARGET)")
        w('\t@echo "✓ Built $(FINAL_TARGET) for $(UNAME_S) ($(ARCH))"')
        w("")

        w("$(BUILD_STAMP):")
        w("\t@rm -f .ace_build_*")
        w("\t@touch $@")
        w("")

        L.extend(fetch_rules)
        L.extend(build_rules)
        L.extend(obj_rules)

        # ---- hashes -------------------------------------------------------
        w("$(HASH_HEADER): $(MODULE_HEADERS)")
        w('\t@echo "// Generated Registration - do not edit" > $@')
        w("\t@for f in $(MODULE_HEADERS); do \\")
        w("\t    HASH=$$(cat $$f | openssl dgst -sha256 | awk '{print $$NF}'); \\")
        w("\t    FULL_NAME=$$(basename $$f); \\")
        w("\t    VAR_NAME=$$(echo $$FULL_NAME | sed 's/\\./_/g'); \\")
        w("\t    printf 'inline const bool _reg_%s = []() { "
          "ETCS::FlatMap<ETCS::Buffer, ETCS::Buffer>::setArena(&ETCS::MemoryArena::getInstance()); "
          "ETCS::Entity::getManifest()[\"%s\"] = \"%s\"; return true; }();\\n' "
          "\"$$VAR_NAME\" \"$$FULL_NAME\" \"$$HASH\" >> $@; \\")
        w("\tdone")
        w("")

        # ---- link ---------------------------------------------------------
        # BUILD_STAMP is a REAL prerequisite, not order-only: it is how a
        # changed architecture, sanitizer or ABI-define set forces a relink.
        # Order-only would let a stale .so built with different flags stand.
        prereqs = (["$(MODULE_DEPS)", "$(HASH_HEADER)", "$(BUILD_STAMP)"]
                   + obj_targets + build_markers)
        order_only = fetch_markers
        w("# Archives come AFTER the translation unit that needs them: gold does")
        w("# not rescan an archive it has already passed, so a dependency listed")
        w("# among the flags resolves only by accident.")
        # Emitted only when there is something to order against -- a module
        # with no fetched dependencies would otherwise get a trailing "|"
        # with nothing after it, which GNU make tolerates and other makes
        # need not.
        oo = (" | " + " ".join(order_only)) if order_only else ""
        w(f"$(FINAL_TARGET): {' '.join(prereqs)}{oo}")
        tail = " ".join(inline_srcs + obj_targets + link_items)
        w(f"\t$(CXX) $(CXXFLAGS) $(EXTRADEFINES) $(LDFLAGS) -o $@ $(SRC_MODULE)"
          + ((" " + tail) if tail.strip() else "") + " $(SYSLIBS)")
        w("")

        # ---- depfile ------------------------------------------------------
        w("# Header dependencies.")
        w("#")
        w("# A separate -MM pass rather than -MMD on the build rule above: that rule")
        w("# compiles AND links in one command, so gcc writes a single <target>.d")
        w("# holding only the LAST source's deps -- a vendored C file, not the module.")
        w("#")
        w("# The order-only prerequisites are load-bearing. `-include $(DEPFILE)`")
        w("# makes make build DEPFILE before ANY goal, and the -MM pass preprocesses")
        w("# the module for real -- so a vendored header that has not been fetched")
        w("# yet is a fatal error on a clean tree rather than a missing edge. Every")
        w("# fetch and build marker is listed here for exactly that reason.")
        w("DEPFILE := $(SRC_MODULE:.cc=.d)")
        dep_order = fetch_markers + build_markers
        w(f"$(DEPFILE): $(SRC_MODULE) $(HASH_HEADER)"
          + ((" | " + " ".join(dep_order)) if dep_order else ""))
        w("\t@$(CXX) $(CXXFLAGS) $(EXTRADEFINES) -MM -MP -MT '$(FINAL_TARGET)' -MF $@ $(SRC_MODULE)")
        w("")
        w("# Skipped for `clean`: -include makes make build DEPFILE before any goal,")
        w("# and a tree too broken to preprocess must still be cleanable.")
        w("ifeq (,$(filter clean,$(MAKECMDGOALS)))")
        w("-include $(DEPFILE)")
        w("endif")
        w("")

        # ---- clean --------------------------------------------------------
        w("clean:")
        w("\trm -f $(FINAL_TARGET) *.o $(HASH_HEADER) $(DEPFILE) .ace_build_*")
        w("\trm -rf .ace_obj")
        for p in clean_paths:
            w(f"\trm -rf {p}")
        w("\t@echo \"✓ Cleaned $(TARGET_BASE_NAME) (vendored sources preserved)\"")
        w("")

        return "\n".join(L)

    def _emit_fetch_rule(self, v, dep, marker):
        src = dep["source"]
        ref, url = src["ref"], src["url"]
        shallow = src.get("shallow", True)
        lines = []
        lines.append(f"# {dep['name']}: pinned at {ref}")
        lines.append(f"{marker}:")
        lines.append(f"\t@if [ ! -d \"$({v}_DIR)/.git\" ]; then \\")
        if shallow:
            lines.append(f"\t    git clone --depth 1 --branch '{ref}' {url} $({v}_DIR) 2>/dev/null \\")
            lines.append(f"\t      || git clone {url} $({v}_DIR); \\")
        else:
            lines.append(f"\t    git clone {url} $({v}_DIR); \\")
        lines.append("\tfi")
        lines.append(f"\t@git -C $({v}_DIR) rev-parse --verify --quiet '{ref}^{{commit}}' >/dev/null \\")
        lines.append(f"\t  || git -C $({v}_DIR) fetch --tags origin '{ref}'")
        lines.append(f"\t@git -C $({v}_DIR) checkout --quiet --detach '{ref}'")
        if src.get("submodules"):
            lines.append(f"\t@git -C $({v}_DIR) submodule update --init --recursive --depth 1")
        lines.append("\t@rm -f $(dir $@).ace_fetched_*")
        lines.append("\t@touch $@")
        lines.append("")
        return "\n".join(lines)

    def _emit_build_rule(self, v, dep, marker, fetch_marker):
        b = dep["build"]
        system = b["system"]
        bd = b.get("build_dir", "build")
        par = "--parallel $(NPROC)" if b.get("parallel", True) else ""

        # The SAME defines the module compiles with (see _emit_makefile).
        # A define that changes struct layout has to reach both halves or
        # the library and its consumer disagree about member offsets --
        # which links, loads, and corrupts memory rather than failing.
        abi = " ".join(f"-D{d}" for d in dep.get("abi_defines", []))
        cflags = (abi + " $(DEP_SANITIZE)").strip()

        lines = []
        lines.append(f"# {dep['name']}: {system}")
        if abi:
            lines.append(f"# ABI defines: {abi} -- also in the module's own CXXFLAGS.")
        lines.append(f"{marker}:" + (f" | {fetch_marker}" if fetch_marker else ""))

        if system == "cmake":
            user = list(b.get("defines", []))
            # Merge rather than append a second -DCMAKE_C_FLAGS: cmake takes
            # the last one and would silently drop whichever lost.
            merged, seen_cflags = [], False
            for d in user:
                if d.startswith("CMAKE_C_FLAGS="):
                    seen_cflags = True
                    merged.append(f'{d} {cflags}'.strip())
                else:
                    merged.append(d)
            if cflags and not seen_cflags:
                merged.append(f"CMAKE_C_FLAGS={cflags}")
            defines = " ".join(f'-D{d}' if "=" not in d or " " not in d
                               else f'-D"{d}"' for d in merged)
            lines.append(f"\t@rm -rf $({v}_DIR)/{bd}")
            lines.append(f"\t@cmake -S $({v}_DIR) -B $({v}_DIR)/{bd} {defines}".rstrip())
            lines.append(f"\t@cmake --build $({v}_DIR)/{bd} {par}".rstrip())
        elif system == "autotools":
            args = " ".join(b.get("configure_args", []))
            targets = " ".join(b.get("targets", []))
            env = f'CFLAGS="{cflags}" ' if cflags else ""
            lines.append(f"\t@cd $({v}_DIR) && {env}./configure {args} "
                         f"&& {env}$(MAKE) {targets}".rstrip())
        elif system == "make":
            targets = " ".join(b.get("targets", []))
            env = f'CFLAGS="{cflags}" ' if cflags else ""
            lines.append(f"\t@{env}$(MAKE) -C $({v}_DIR) {targets}".rstrip())
        # "none" emits no build step; the marker exists only to order the fetch.

        lines.append("\t@mkdir -p $(dir $@)")
        lines.append("\t@rm -f $(dir $@).ace_built_*")
        lines.append("\t@touch $@")
        lines.append("")
        return "\n".join(lines)

    def _emit_obj_rule(self, v, dep, sources, gate=None):
        # Own flags, plus the ABI defines (these objects are linked INTO the
        # module, so they must agree with it) and the sanitizer -- these are
        # cheap to rebuild, unlike a cmake dependency, so they follow the
        # module rather than DEP_SANITIZE.
        abi = " ".join(f"-D{d}" for d in dep.get("abi_defines", []))
        cflags = " ".join(x for x in (" ".join(sources.get("cflags", [])),
                                      abi, "$(SANITIZE)") if x)
        lines = []
        lines.append(f"# {dep['name']}: compiled with its own flags, not the module's")
        for ext, comp in ((".c", "$(CC)"), (".cc", "$(CXX)")):
            # BUILD_STAMP real, gates order-only: the stamp must force a
            # recompile when flags change; the gates only have to exist first.
            gates = (" | " + " ".join(gate)) if gate else ""
            lines.append(f".ace_obj/{v}_%.o: $({v}_DIR)/%{ext} $(BUILD_STAMP){gates}")
            lines.append("\t@mkdir -p $(dir $@)")
            lines.append(f"\t{comp} {cflags} -c $< -o $@")
            lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # generation
    # ------------------------------------------------------------------

    def generate_makefile(self, module, force=False, quiet=False, silent=False):
        """Write module/Makefile from its manifest. Returns True if written."""
        try:
            m = self.load_manifest(module, resolve_pins=True, silent=silent)
        except ManifestError as e:
            print(f"  {RED}[-]{RESET} {module}: {e}")
            return False

        target_dir = self._module_dir(module)
        if not target_dir.exists():
            print(f"  {RED}[-]{RESET} {module}: no module directory at {target_dir}")
            return False

        makefile = target_dir / "Makefile"
        if makefile.exists() and not force:
            if not quiet:
                print(f"  {DIM}Makefile present; ace manifest generate {module} --force "
                      f"to rewrite it.{RESET}")
            return False

        try:
            text = self._emit_makefile(m)
        except Exception as e:
            print(f"  {RED}[-]{RESET} {module}: generation failed: {e}")
            return False

        makefile.write_text(text)
        if not quiet:
            print(f"  {GREEN}[+]{RESET} generated {module}/Makefile "
                  f"{DIM}({len(text.splitlines())} lines){RESET}")
        return True

    def ensure_makefile(self, module):
        """Regenerate a missing Makefile. Called on the build path.

        Generated Makefiles are gitignored, so a fresh clone has none. This is
        what makes that a non-event rather than a build failure. An existing
        Makefile is never overwritten here -- only `--force` does that, so a
        module that predates its manifest keeps building until someone
        deliberately migrates it.
        """
        if not self.has_manifest(module):
            return False
        makefile = self._module_dir(module) / "Makefile"
        if makefile.exists():
            return False
        print(f"[*] {module}/Makefile is missing -- regenerating from manifest.")
        return self.generate_makefile(module, quiet=False)

    # ------------------------------------------------------------------
    # loaders
    # ------------------------------------------------------------------
    #
    # Loaders share ONE Makefile, selected by FILE= -- so unlike modules there
    # is one generated file for the whole directory, not one per target. The
    # default manifest describes every loader; a <Name>.loader.json exists
    # only for a loader that needs something extra, and becomes an
    # ifeq ($(FILE),<Name>) block inside the shared file.
    #
    # The extra that actually matters is inherits_modules. A loader that
    # compiles a module's internal headers -- rather than dlopening it and
    # driving the tag surface -- needs that module's vendored include paths
    # and archives. SCSRealTesterLoader does exactly this to reach TryClaim /
    # NoteSubmit / NoteComplete, which are a C++ protocol between the accept
    # chain and the completion callbacks and are not reachable through the
    # work-function surface at all. Without the inherited flags,
    # #include "mbedtls/ssl.h" resolves against /usr/include instead of the
    # module's vendored copy, and the mismatch surfaces as a signature error
    # in a header nobody edited.

    def _loader_manifest_dir(self):
        return self._manifest_dir() / "loaders"

    def _loader_manifests(self):
        """(default, {name: manifest}). Missing default is not an error --
        it just means loaders are not manifest-driven in this tree yet."""
        d = self._loader_manifest_dir()
        if not d.is_dir():
            return None, {}
        default, overrides = None, {}
        for p in sorted(d.glob("*.loader.json")):
            try:
                m = json.loads(p.read_text())
            except json.JSONDecodeError as e:
                print(f"  {RED}[-]{RESET} {p.name}: {e}")
                continue
            if p.name == "default.loader.json":
                default = m
            else:
                overrides[p.name[:-len(".loader.json")]] = m
        return default, overrides

    def _inherited_module_flags(self, module_names, silent=False):
        """Include paths and link artifacts a loader inherits from modules.

        Paths are rewritten relative to loaders/, since that is where the
        generated Makefile runs. Link order is preserved exactly as the
        module's manifest declares it.

        Returns (includes, links, syslibs, errors). A caller that gets a
        non-empty `errors` MUST NOT emit a Makefile: a loader whose inherited
        include paths silently went missing still compiles, because the
        headers it wanted exist in /usr/include too -- just a different
        version of them. That failure surfaces as a signature mismatch in a
        header nobody edited, which is precisely the bug this inheritance
        exists to prevent. Degrading quietly here would rebuild it.
        """
        includes, links, syslibs, errors = [], [], [], []
        abi = []
        for name in module_names:
            try:
                m = self.load_manifest(name, resolve_pins=True, silent=silent)
            except ManifestError as e:
                errors.append(f"cannot inherit from {name}: {e}")
                continue
            # ABI defines travel with the headers. A loader that compiles a
            # module's vendored headers without them sees a different struct
            # layout than the library it links against -- the same silent
            # corruption the module itself is protected from.
            for dep in m.get("requires", {}).get("vendor", []):
                for d in dep.get("abi_defines", []):
                    if d not in abi:
                        abi.append(d)
            base = f"../modules/{name}"
            for dep in m.get("requires", {}).get("vendor", []):
                src = dep["source"]
                ddir = f"{base}/{src['path']}" if src["type"] == "vendored" \
                    else f"{base}/{dep['name']}"
                prov = dep.get("provides", {})
                for inc in prov.get("include", []):
                    includes.append(f"-I{ddir}" if inc == "." else f"-I{ddir}/{inc}")
                for art in prov.get("link", []):
                    path = f"{ddir}/{art['path']}"
                    links.append(
                        f"-Wl,--whole-archive {path} -Wl,--no-whole-archive"
                        if art.get("mode") == "whole_archive" else path)
            for lib in m.get("build", {}).get("Linux", {}).get("system_libs", []):
                if lib not in syslibs:
                    syslibs.append(lib)
        return includes, links, syslibs, errors, abi

    def _emit_loaders_makefile(self, default, overrides, silent=False):
        """Render loaders/Makefile from the default manifest plus overrides.

        Raises ManifestError if any override cannot be fully resolved -- see
        _inherited_module_flags on why a partial emit is worse than none.
        """
        common = default.get("build", {}).get("common", {})
        L = []
        w = L.append

        w("# " + "=" * 68)
        w(GENERATED_MARKER)
        w("#")
        w("#   source:      <ace tool>/manifests/loaders/*.loader.json")
        w("#   regenerate:  ace manifest generate loaders")
        w("#")
        w("# One Makefile serves every loader, selected by FILE=. A loader with")
        w("# its own <Name>.loader.json gets an ifeq block below; every other")
        w("# loader builds from the defaults alone.")
        w("# " + "=" * 68)
        w("")
        w("UNAME_S := $(shell uname -s)")
        w("NPROC   := $(shell nproc)")
        w("CXX := g++")
        w("BIN_DIR := ../bin")
        w("")
        w("# Debug info: make DEBUG=1, off by default. A sanitizer build forces")
        w("# it on -- see the module Makefiles' own note.")
        w("DEBUGFLAGS :=")
        w("ifeq ($(DEBUG),1)")
        w("    DEBUGFLAGS := -g")
        w("endif")
        w("")
        w("# Sanitizers: make ASAN=1 / make TSAN=1, mutually exclusive.")
        w("#")
        w("# A loader and the modules it dlopens share one address space, so they")
        w("# must be built the SAME way -- `ace make module X ASAN=1` for every")
        w("# module the loader will load, not just the loader. A sanitizer runtime")
        w("# that sees only half the process reports nonsense.")
        w("SANITIZE :=")
        w("ifeq ($(ASAN),1)")
        w("ifeq ($(TSAN),1)")
        w("    $(error ASAN=1 and TSAN=1 are mutually exclusive)")
        w("endif")
        w("    SANITIZE := -fsanitize=address -fno-omit-frame-pointer")
        w("endif")
        w("ifeq ($(TSAN),1)")
        w("    SANITIZE := -fsanitize=thread -fno-omit-frame-pointer")
        w("endif")
        w("ifneq ($(SANITIZE),)")
        w("    DEBUGFLAGS := -g")
        w("endif")
        w("")

        cxx = [f.format(std=default.get("loader", {}).get("std", "c++17"))
               for f in BASE_LOADER_CXXFLAGS]
        cxx += [f"-D{d}" for d in common.get("defines", [])]
        cxx += common.get("cxxflags", [])
        cxx += ["$(DEBUGFLAGS)", "$(SANITIZE)"]
        w("CXXFLAGS := " + " \\\n            ".join(cxx))
        w("")

        exports = default.get("produces", {}).get("exports")
        for plat, cond, kw in (("Linux", "Linux", "ifeq"),
                               ("Win", "Windows_NT", "else ifeq")):
            blk = default.get("build", {}).get(plat, {})
            w(f"{kw} ($(UNAME_S),{cond})")
            parts = blk.get("ldflags", []) + ["-l" + l for l in blk.get("system_libs", [])]
            if plat == "Linux" and exports:
                # Same ELF-only reasoning as a module's own version script
                # (see _emit_makefile): silently ignored on Win, which would
                # read as an enforced export surface that isn't one.
                #
                # A loader needs this for the opposite reason a module does.
                # A module restricts what it OFFERS; a loader linked
                # -rdynamic (so a module's static-init can find
                # ETCS_GetLoaderManifest via dlsym(RTLD_DEFAULT, ...))
                # would otherwise offer every symbol -fvisibility=hidden
                # happened not to catch. The version script is what keeps
                # that an audited whitelist instead of a side effect.
                parts.append(f"-Wl,--version-script={exports}")
            w(f"    LDFLAGS := {' '.join(parts)}".rstrip())
        w("else")
        w("    $(error Unsupported platform: $(UNAME_S))")
        w("endif")
        w("")

        w("# Per-loader additions. EXTRA_LINK is kept OUT of LDFLAGS on purpose:")
        w("# it lands after the translation unit on the command line, because")
        w("# gold does not rescan an archive it has already passed.")
        w("EXTRA_CXXFLAGS :=")
        w("EXTRA_LINK :=")
        w("")

        for name in sorted(overrides):
            o = overrides[name]
            ob = o.get("build", {}).get("common", {})
            inc, links, syslibs, errors, abi = self._inherited_module_flags(
                o.get("inherits_modules", []), silent=silent)
            if errors:
                raise ManifestError(
                    f"loader {name}: " + "; ".join(errors)
                    + "\n      Refusing to emit loaders/Makefile: without the inherited"
                      "\n      flags this loader would still COMPILE, against whatever"
                      "\n      copy of those headers is installed system-wide, and fail"
                      "\n      with a signature mismatch in a header nobody edited.")
            extra_cxx = [f"-D{d}" for d in abi] + inc + ob.get("cxxflags", []) + \
                [f"-D{d}" for d in ob.get("defines", [])]
            extra_link = links + ["-l" + l for l in syslibs] + \
                ob.get("link", [])
            if not extra_cxx and not extra_link:
                continue
            w(f"ifeq ($(FILE),{name})")
            if o.get("inherits_modules"):
                w(f"    # inherits: {', '.join(o['inherits_modules'])}")
            if extra_cxx:
                w(f"    EXTRA_CXXFLAGS += {' '.join(extra_cxx)}")
            if extra_link:
                w(f"    EXTRA_LINK += {' '.join(extra_link)}")
            w("endif")
            w("")

        w("# If FILE is specified, build only that one; otherwise every *Loader.cc.")
        w("ifdef FILE")
        w("    LOADER_SRCS := $(FILE).cc")
        w("else")
        w("    LOADER_SRCS := $(wildcard *Loader.cc)")
        w("endif")
        w("LOADER_BINS := $(LOADER_SRCS:.cc=)")
        w("")
        w(".PHONY: all clean copy_loaders")
        w("all: $(LOADER_BINS) etcs copy_loaders")
        w("")
        w("%Loader: %Loader.cc")
        w("\t$(CXX) $(CXXFLAGS) $(EXTRA_CXXFLAGS) $(EXTRADEFINES) -o Run_$@ $< "
          "$(EXTRA_LINK) $(LDFLAGS)")
        w("")
        w("etcs: etcs.cc")
        w("\t$(CXX) $(CXXFLAGS) $(EXTRA_CXXFLAGS) $(EXTRADEFINES) -o $@ $< "
          "$(EXTRA_LINK) $(LDFLAGS)")
        w("")
        w("copy_loaders:")
        w("\t@mkdir -p $(BIN_DIR)")
        w('\t@echo "--- Moving Loaders to $(BIN_DIR)/ ---"')
        w("\t@found=0; \\")
        w("\tfor f in Run_*Loader etcs; do \\")
        w('\t    if [ -f "$$f" ]; then \\')
        w('\t        mv -f "$$f" $(BIN_DIR)/; \\')
        w('\t        echo " [✓] Moved: $$f -> $(BIN_DIR)/"; \\')
        w("\t        found=1; \\")
        w("\t    fi; \\")
        w("\tdone; \\")
        w("\tif [ $$found -eq 0 ]; then echo \" [!] No binaries found to move\"; fi")
        w("")
        w("clean:")
        w("\trm -f Run_*Loader etcs *.o")
        w("\t@for f in Run_*Loader etcs; do rm -f $(BIN_DIR)/$$f; done")
        w("")
        return "\n".join(L)

    def generate_loaders_makefile(self, force=False, quiet=False):
        default, overrides = self._loader_manifests()
        if default is None:
            if not quiet:
                print(f"  {DIM}No default.loader.json; loaders are not "
                      f"manifest-driven yet.{RESET}")
            return False

        loaders_dir = self.ace_root / "loaders"
        if not loaders_dir.is_dir():
            print(f"  {RED}[-]{RESET} no loaders directory at {loaders_dir}")
            return False

        makefile = loaders_dir / "Makefile"
        if makefile.exists() and not force:
            if not quiet:
                print(f"  {DIM}loaders/Makefile present; "
                      f"ace manifest generate loaders --force to rewrite it.{RESET}")
            return False

        try:
            text = self._emit_loaders_makefile(default, overrides)
        except ManifestError as e:
            print(f"  {RED}[-]{RESET} {e}")
            return False
        makefile.write_text(text)
        if not quiet:
            extra = f" (+{len(overrides)} override(s))" if overrides else ""
            print(f"  {GREEN}[+]{RESET} generated loaders/Makefile{extra} "
                  f"{DIM}({len(text.splitlines())} lines){RESET}")
        return True

    def ensure_loaders_makefile(self):
        """Regenerate loaders/Makefile when missing. Build-path hook."""
        default, _ = self._loader_manifests()
        if default is None:
            return False
        if (self.ace_root / "loaders" / "Makefile").exists():
            return False
        print("[*] loaders/Makefile is missing -- regenerating from manifests.")
        return self.generate_loaders_makefile()

    # ------------------------------------------------------------------
    # system packages, folded into the existing deps surface
    # ------------------------------------------------------------------

    def manifest_system_packages(self):
        """Every system package required by any manifest, as (package, probe)
        pairs matching the vocabulary ace_deps._run_probe already speaks.

        Resolution mirrors _detect_distro: the first distro id that the
        manifest names wins, so 'debian' covers ubuntu and raspbian without
        each needing its own block.
        """
        wanted = []
        seen = set()
        distros = self._detect_distro()
        for path in sorted(self._manifest_dir().glob("*.json")):
            try:
                m = json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            table = m.get("requires", {}).get("system", {})
            for distro in distros:
                if distro in table:
                    for entry in table[distro]:
                        key = entry["package"]
                        if key not in seen:
                            seen.add(key)
                            wanted.append((key, entry.get("probe", "none")))
                    break
        return wanted

    # ------------------------------------------------------------------
    # CLI
    # ------------------------------------------------------------------

    def _pin_state(self, module):
        """Short annotation for `list`: unpinned deps are the one thing that
        stops a manifest from building, so they belong in the overview."""
        try:
            m = json.loads(self._manifest_path(module).read_text())
        except (json.JSONDecodeError, OSError):
            return f"  {RED}unreadable{RESET}"
        loose = [d["name"] for d in m.get("requires", {}).get("vendor", [])
                 if d.get("source", {}).get("type") == "git"
                 and d["source"].get("ref") in UNPINNED]
        return f"  {YELLOW}unpinned: {', '.join(loose)}{RESET}" if loose else ""

    def _all_manifests(self):
        """Modules with a manifest of their OWN. default.json is excluded --
        it names no module and is not one."""
        d = self._manifest_dir()
        if not d.is_dir():
            return []
        return sorted(p.stem for p in d.glob("*.json") if p.name != "default.json")

    def _defaulted_modules(self):
        """Modules present in the tree that will build from default.json.

        Discovered from the tree rather than from manifests/, since the whole
        point is that they have no file there to enumerate."""
        if not self._default_manifest_path().is_file():
            return []
        mods = self.ace_root / "modules"
        if not mods.is_dir():
            return []
        own = set(self._all_manifests())
        found = []
        for p in sorted(mods.iterdir()):
            if p.name.startswith(".") or p.name in own:
                continue
            if (p / f"{p.name}.cc").is_file():
                found.append(p.name)
        return found

    def manifest(self, args):
        """Dispatch for `ace manifest ...`."""
        sub = args[0] if args else "list"

        if sub == "list":
            names = self._all_manifests()
            default, overrides = self._loader_manifests()
            if not names and default is None:
                print(f"  {DIM}No manifests in {self._manifest_dir()}{RESET}")
                return
            print(f"\n--- Manifests ({self._manifest_dir()}) ---\n")
            for n in names:
                mk = self._module_dir(n) / "Makefile"
                state = f"{GREEN}generated{RESET}" if mk.exists() else f"{YELLOW}missing{RESET}"
                pins = self._pin_state(n)
                print(f"  {CYAN}{n:<24}{RESET} Makefile: {state}{pins}")
            defaulted = self._defaulted_modules()
            if defaulted:
                print(f"\n  {DIM}building from default.json (nothing of their "
                      f"own to declare):{RESET}")
                for n in defaulted:
                    mk = self._module_dir(n) / "Makefile"
                    state = (f"{GREEN}generated{RESET}" if mk.exists()
                             else f"{YELLOW}missing{RESET}")
                    print(f"    {CYAN}{n:<22}{RESET} Makefile: {state}")
            if default is not None:
                mk = self.ace_root / "loaders" / "Makefile"
                state = f"{GREEN}generated{RESET}" if mk.exists() else f"{YELLOW}missing{RESET}"
                print(f"\n  {CYAN}{'loaders':<24}{RESET} Makefile: {state}")
                for n in sorted(overrides):
                    inh = overrides[n].get("inherits_modules", [])
                    note = f" {DIM}inherits {', '.join(inh)}{RESET}" if inh else ""
                    print(f"    {DIM}override:{RESET} {n}{note}")
            print()
            return

        if sub == "check":
            names = args[1:] or self._all_manifests()
            bad = 0
            for n in names:
                try:
                    self.load_manifest(n)
                    print(f"  {GREEN}OK    {RESET} {n}")
                except ManifestError as e:
                    bad += 1
                    print(f"  {RED}FAIL  {RESET} {n}: {e}")
            if bad:
                print(f"\n  {RED}{bad} manifest(s) rejected.{RESET}")
            return

        if sub == "show" and len(args) > 1:
            try:
                print(self._emit_makefile(self.load_manifest(args[1])))
            except ManifestError as e:
                print(f"  {RED}[-]{RESET} {e}")
            return

        if sub == "clean":
            names = [a for a in args[1:] if not a.startswith("--")]
            if not names:
                n = self.clean_all_makefiles()
                print(f"\n  {n} generated Makefile(s) removed. The next build "
                      f"regenerates them.\n")
            elif names == ["loaders"]:
                self.clean_loaders_makefile()
            else:
                for n_ in names:
                    self.clean_makefile(n_)
            return

        if sub == "generate":
            force = "--force" in args
            names = [a for a in args[1:] if not a.startswith("--")]
            if names == ["loaders"]:
                self.generate_loaders_makefile(force=force)
                return
            for n in (names or self._all_manifests()):
                self.generate_makefile(n, force=force)
            if not names:
                self.generate_loaders_makefile(force=force)
            return

        print(f"[-] Unknown manifest command: '{sub}'")
        print(f"    Usage: ace manifest {{ list | check [mod...] | show <mod> "
              f"| generate [mod...|loaders] [--force] | clean [mod...|loaders] }}")
