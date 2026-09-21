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

from .ace_common import (CYAN, YELLOW, GREEN, RED, RESET, DIM, ORANGE)


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
    "-Wextra", "-O2", "-I../..", "-pipe", "$(PLT_FLAGS)",
    "-DETCS_LOADER", r'-DETCS_MODULE_NAME=\"ROOT\"',
]

# WHERE THE TREE IS, ANSWERED BY THE THING THAT KNOWS.
#
# ACE_ROOT is an ACE concept -- this tool is what locates the tree, and every
# generated Makefile already sits inside it. So the runtime is TOLD, at build
# time, rather than asking: core/CommandExecutor.h used to popen `ace root`
# from inside the process to expand ACE_ROOT in a script statement, which put
# a python CLI on the critical path of a running server and failed silently
# wherever `ace` was not on that process's PATH -- a systemd unit, a stripped
# shell, a container. Baked in, it also joins the build fingerprint, so a tree
# that MOVED rebuilds instead of resolving to where it used to be.
#
# Absolute and computed here, not $(shell ace root) in the Makefile: a
# subprocess per build is the same mistake one layer up, and the value is
# already in hand.
ACE_ROOT_DEFINE = r'-DETCS_ACE_ROOT=\"{root}\"'

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



def _vendor_profiles(m, module_name):
    """requires.vendor as {profile: [dep, ...]}.

    Profile keys mirror the source tree: the module's own name (the
    general-headers folder, modules/<Mod>/<Mod>/) is the universal
    profile, carried on every platform the module builds; a platform
    directory name (Linux/Win/Web/OS) carries only that platform. A plain
    list is shorthand for the universal profile.
    """
    if module_name in PLATFORM_DIRS:
        raise ManifestError(
            f"module name {module_name!r} collides with a platform directory "
            f"name -- its universal vendor profile key would be ambiguous")
    raw = m.get("requires", {}).get("vendor", [])
    if isinstance(raw, list):
        return {module_name: raw}
    if not isinstance(raw, dict):
        raise ManifestError(
            "requires.vendor must be a list or a profile-keyed object "
            f'{{"{module_name}": [...], "Linux": [...], ...}}')
    out = {}
    for key, deps in raw.items():
        if key != module_name and key not in PLATFORM_DIRS:
            raise ManifestError(
                f"vendor profile {key!r} is neither this module's name "
                f"({module_name!r}, the universal profile) nor a platform "
                f"directory ({', '.join(PLATFORM_DIRS)})")
        if not isinstance(deps, list):
            raise ManifestError(f"vendor profile {key!r} must be a list")
        out[key] = deps
    return out


def _vendor_union(profiles):
    """Every profile's dependencies, deduplicated by name, in order.

    A name repeated across profiles must repeat identically -- profiles
    that disagree about what a dependency IS is a manifest bug, not a
    merge to arbitrate.
    """
    seen, order = {}, []
    for deps in profiles.values():
        for dep in deps:
            name = dep.get("name", "<unnamed>")
            if name in seen:
                if json.dumps(seen[name], sort_keys=True) != json.dumps(dep, sort_keys=True):
                    raise ManifestError(
                        f"dependency {name!r} appears in multiple vendor profiles "
                        f"with different declarations -- declare it once per "
                        f"carrying profile instead")
                continue
            seen[name] = dep
            order.append(dep)
    return order


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

    def makefile_state(self, path):
        """What is sitting at that path, in the three states that matter.

        `generated` and `missing` were the only two reported, so a Makefile
        this tool did not write -- a module deliberately kept by hand, or one
        left behind by an older layout -- printed as `generated` and looked
        managed. It is not: nothing regenerates it, `manifest clean` steps
        around it, and its flags drift from every other module's silently.

        Same marker `_is_generated` deletes on, so the listing and the delete
        can never disagree about which files this tool owns.
        """
        if not path.is_file():
            return f"{YELLOW}missing{RESET}"
        if self._is_generated(path):
            return f"{GREEN}generated{RESET}"
        return f"{ORANGE}custom{RESET}"

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
        for dep in _vendor_union(_vendor_profiles(m, module)):
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

        profiles = _vendor_profiles(m, module)
        module_platforms = m.get("module", {}).get("platforms", ["Linux"])
        for p in profiles:
            if p != module and p not in module_platforms:
                print(f"  {YELLOW}[!]{RESET} {module}: vendor profile '{p}' is outside "
                      f"this module's platforms {module_platforms} -- carried nowhere.")
        for dep in _vendor_union(profiles):
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
        profiles = _vendor_profiles(m, name)
        vendor = _vendor_union(profiles)
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
        w("# Build stamp -- architecture, PLATFORM, sanitizer, ABI-define set.")
        w("# Real prerequisite, not order-only: switching any of them must force")
        w("# a relink. The platform tag exists because uname reports the HOST")
        w("# under emscripten, so native and web artifacts of one module would")
        w("# otherwise share a stamp and switching between them would relink")
        w("# nothing.")
        w("PLATFORM_TAG :=")
        w("PLT_FLAGS := -fno-plt")
        w("ifdef EMSCRIPTEN")
        w("  PLATFORM_TAG := _web")
        w("  # wasm has no procedure linkage table -- see CXXFLAGS.")
        w("  PLT_FLAGS :=")
        w("endif")
        w(f"BUILD_STAMP := .ace_build_$(ARCH)$(PLATFORM_TAG)$(DBG_SUFFIX)$(SAN_SUFFIX){abi_tag}")
        w("")

        # ---- per-dependency variables ------------------------------------
        # Markers, sources, objects and link items are emitted as VARIABLES
        # and referenced deferred (at rule-expansion time), so a platform
        # block can void them for dependencies that platform does not
        # carry -- an empty variable in a prerequisite list is no
        # prerequisite: nothing fetches, builds or links.
        fetch_markers, build_markers, obj_targets = [], [], []
        inline_srcs, link_items = [], []
        obj_rules, fetch_rules, build_rules = [], [], []
        clean_paths = []
        dep_carriage = []  # (var, carried platforms, include flags)

        # Param is dep_name, NOT name: the module's own name (the universal
        # profile key) is captured from the enclosing scope, and a parameter
        # called `name` would shadow it -- profiles.get(name) would then look
        # up the DEPENDENCY's name as a profile key and silently find nothing.
        def carried(dep_name):
            """Platforms carrying this dependency: every module platform if
            it sits in the module's own (universal) profile, plus each
            platform profile naming it."""
            plats = set()
            if any(d.get("name") == dep_name for d in profiles.get(name, [])):
                plats.update(platforms)
            for p, deps in profiles.items():
                if p != name and any(d.get("name") == dep_name for d in deps):
                    plats.add(p)
            return plats

        for dep in vendor:
            v = _var(dep["name"])
            src = dep["source"]
            prov = dep.get("provides", {})

            if src["type"] == "vendored":
                w(f"{v}_DIR := {src['path']}")
            else:
                w(f"{v}_DIR := {dep['name']}")
            w("")

            # -isystem, NOT -I. A vendored dependency's headers are read, not
            # maintained, here: stb_image_write alone accounts for eight
            # -Wmissing-field-initializers in every build that includes it, and
            # a warning nobody in this tree can act on is a warning that
            # teaches people to scroll past the ones they can. -isystem keeps
            # the header on the path and takes it off the report.
            incs = [f"-isystem $({v}_DIR)/{inc}" if inc != "." else f"-isystem $({v}_DIR)"
                    for inc in prov.get("include", [])]
            dep_carriage.append((v, carried(dep["name"]), incs))

            # fetch
            if src["type"] == "git":
                marker = f"$({v}_DIR)/.ace_fetched_{_sanitize(src['ref'])}"
                w(f"{v}_FETCHMK := {marker}")
                fetch_markers.append(f"$({v}_FETCHMK)")
                fetch_rules.append(self._emit_fetch_rule(v, dep, marker))

            # build
            if dep.get("build"):
                bd = dep["build"].get("build_dir", "build")
                marker = (f"$({v}_DIR)/{bd}/.ace_built_$(ARCH)$(DEP_SAN_SUFFIX)"
                          + _abi_tag(dep.get("abi_defines", [])))
                w(f"{v}_BUILDMK := {marker}")
                build_markers.append(f"$({v}_BUILDMK)")
                build_rules.append(
                    self._emit_build_rule(
                        v, dep, marker,
                        f"$({v}_FETCHMK)" if src["type"] == "git" else None))
                clean_paths.append(f"$({v}_DIR)/{bd}")

            sources = prov.get("sources")
            if sources:
                globs = " ".join(self._dep_source_expr(v, g)
                                 for g in sources.get("include", []))
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
                        f"$({v}_FETCHMK)" if src["type"] == "git" else None,
                        f"$({v}_BUILDMK)" if dep.get("build") else None,
                    ) if mk]
                    obj_rules.append(self._emit_obj_rule(v, dep, sources, gate))
                else:
                    inline_srcs.append(f"$({v}_SRCS)")
                w("")

            dep_link = []
            for art in prov.get("link", []):
                path = f"$({v}_DIR)/{art['path']}"
                if art.get("mode") == "whole_archive":
                    dep_link.append(f"-Wl,--whole-archive {path} -Wl,--no-whole-archive")
                else:
                    dep_link.append(path)
            # One variable per dependency, joined: assigning inside the loop
            # (last wins) while appending per artifact linked the LAST entry
            # once per artifact and dropped the rest.
            w(f"{v}_LINK := {' '.join(dep_link)}")
            if dep_link:
                link_items.append(f"$({v}_LINK)")

        # ---- flags --------------------------------------------------------
        cxx = [f.format(std=std) for f in BASE_CXXFLAGS]
        cxx.append(r'-DETCS_MODULE_NAME=\"$(TARGET_BASE_NAME)\"')
        cxx.append(ACE_ROOT_DEFINE.format(root=str(self.ace_root)))
        cxx += ["-I.", "-I../.."]
        # Vendored -I flags are emitted inside the platform blocks, not here:
        # CXXFLAGS is simply expanded at this point, so a global -I could
        # never be retracted for a platform that does not carry the dep.
        # ABI defines, emitted here AND into every dependency's own build (see
        # _emit_build_rule). One field, two places, because that is what
        # correctness requires -- having to remember it in both by hand is how
        # a struct layout ends up disagreeing across a link.
        cxx += [f"-D{d}" for d in abi_defines]
        cxx += [f"-D{d}" for d in common.get("defines", [])]
        cxx += common.get("cxxflags", [])
        # -fno-plt ONLY WHERE THERE IS A PLT. It is about the ELF procedure
        # linkage table; wasm has none, so emscripten's clang accepts the flag,
        # ignores it, and says "argument unused during compilation" once per
        # translation unit. Native builds still get it.
        cxx += ["-pipe", "$(PLT_FLAGS)", "$(DEBUGFLAGS)", "$(SANITIZE)",
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

            # Void the variables of dependencies this platform does not carry
            # (vendor profiles). Every downstream reference -- prerequisites,
            # depfile gate, link tail -- expands deferred, so empty means
            # absent: no fetch, no build, no link.
            for v_, plats_, _incs in dep_carriage:
                if plat not in plats_:
                    w(f"    {v_}_SRCS :=")
                    w(f"    {v_}_OBJS :=")
                    w(f"    {v_}_LINK :=")
                    w(f"    {v_}_FETCHMK :=")
                    w(f"    {v_}_BUILDMK :=")
            inc_here = [i for _v, plats_, incs in dep_carriage
                        if plat in plats_ for i in incs]
            if inc_here:
                w(f"    CXXFLAGS += {' '.join(inc_here)}")

            if plat == "Web":
                # Web contract: facts about what a module under emscripten IS,
                # not manifest preferences. -pthread and -fwasm-exceptions
                # must match the loader's MAIN module exactly or the browser
                # refuses instantiation; wasm exceptions because the JS
                # default does not survive dylink (work functions throw).
                #
                # BASE's -fvisibility=hidden STAYS, and not for tidiness: it
                # is what makes each header-inline static (EventNode,
                # ThreadPool, MemoryArena, the RID seed) this module's OWN,
                # as on native. A default-visibility definition is not
                # dso_local under -fPIC, so wasm codegen reaches even the
                # module's own copy through the GOT, and dylink resolves that
                # import to the loader's -- one shared singleton of
                # everything core/ documents as per-DSO. Exports do not need
                # default: wasm-ld has no version script, and a side module
                # exports exactly what is marked visibility("default"), which
                # ETCS_API puts on every symbol the loader dlsym()s.
                w("    CXXFLAGS += -pthread -fwasm-exceptions")
                # Vendored C compiles through $(CC); a native gcc object
                # cannot link into a wasm side module.
                w(f"    CC := {blk.get('cc', 'emcc')}")
                # AND WITH THE MODULE'S TARGET FEATURES. A vendored object is
                # compiled "with its own flags, not the module's" (see the obj
                # rule), which is right for optimisation and defines and wrong
                # for -pthread: a threaded module is linked --shared-memory, and
                # wasm-ld refuses any object in it that was not compiled with
                # atomics and bulk-memory -- which is what -pthread turns on.
                # So the one flag that is a TARGET rather than a preference is
                # carried to every vendored object here.
                w("    DEP_TARGET_FLAGS := -pthread -fPIC")
                # em++ is the Web default, like emcc above: manifests name a
                # compiler only when it is NOT em++.
                if not blk.get("compiler"):
                    w("    CXX := em++")
            if blk.get("compiler"):
                w(f"    CXX := {blk['compiler']}")
            if blk.get("cxxflags"):
                # Web: -sSIDE_MODULE belongs on the link line (emitted below).
                # A stale manifest that still lists it under cxxflags would
                # pass it to the compile step harmlessly on some em++ versions
                # and confuse others -- drop it here; USE_GLFW-style -s flags
                # stay on CXXFLAGS so the port headers resolve at compile.
                cxf = list(blk["cxxflags"])
                if plat == "Web":
                    cxf = [f for f in cxf
                           if f.replace(" ", "") not in
                           ("-sSIDE_MODULE", "-sSIDE_MODULE=1", "-sSIDE_MODULE=2")]
                if cxf:
                    w(f"    CXXFLAGS += {' '.join(cxf)}")
            if blk.get("defines"):
                w(f"    CXXFLAGS += {' '.join('-D' + d for d in blk['defines'])}")

            ext = ".wasm" if plat == "Web" else (".dll" if plat == "Win" else ".so")
            w(f"    FINAL_TARGET := $(TARGET_BASE_NAME){ext}")

            # Under emscripten a module IS a side module: -sSIDE_MODULE
            # replaces -shared; -pthread/-fwasm-exceptions ride the link
            # line for the same must-match reasons as the compile line.
            #
            # -sASYNCIFY IS IN THAT MUST-MATCH SET, and leaving it off here
            # while the loader carries it is not a missing optimisation -- it
            # is a broken program. Asyncify unwinds and rewinds the whole
            # stack, and it can only do that through frames it INSTRUMENTED.
            # An emscripten_sleep reached from a side module therefore unwinds
            # out through uninstrumented frames and comes back wrong on the
            # rewind: the observed failure is "TypeError: resolved is not a
            # function" inside a dylink lazy-symbol stub, under
            # doRewind/handleSleep, after which the runtime is dead and never
            # reaches drive_main_loop_then_exit -- so the terminal never opens.
            # Every cooperative pause in ETCS is in a module, not the loader
            # (etcs_cooperative_pause_ms's call sites are all WindowProvider),
            # so with the flag on the loader alone NO sleep in the program is
            # instrumented end to end.
            #
            # LINK LINE ONLY, unlike -fwasm-exceptions. Wasm exceptions change
            # CODEGEN, so they have to be on the compile line too; Asyncify is
            # a Binaryen pass over the finished wasm, and for a side module the
            # SIDE_MODULE link is where that wasm is finished.
            # No -sASYNCIFY here either: instrumented exports cannot be tabled
            # by a pool thread. The loader block below says why in full.
            ld = (["-sSIDE_MODULE", "-pthread", "-fwasm-exceptions"]
                  if plat == "Web" else ["-shared"])
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
        if "Web" not in platforms:
            # Without a Web branch, EMSCRIPTEN=1 falls through to the Linux
            # branch (uname reports Linux under emsdk) and builds a native
            # .so wearing a _web stamp. Refuse instead.
            w("ifeq (,$(filter clean,$(MAKECMDGOALS)))")
            w("ifdef EMSCRIPTEN")
            w(f"    $(error {name} declares no Web platform -- add \"Web\" to module.platforms in its manifest)")
            w("endif")
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

        # ---- runtime assets ------------------------------------------------
        #
        # Files a module needs AT RUNTIME that are not linked into it --
        # RenderProvider's compiled SPIR-V is the first case. They belong
        # beside the .so in bin/, because that is the one directory the
        # module can find without being told: dladdr gives it its own path,
        # and everything else is a guess about the caller's cwd.
        #
        # Without this the shader path had to be passed in from the script
        # and resolved against the process's working directory, so the same
        # script worked from the repo root and produced a window that never
        # painted from anywhere else. An asset that ships with the module
        # should be installed with the module.
        assets = produces.get("assets", [])
        asset_rules = []
        if assets:
            for a in assets:
                src = a.get("from", "")
                dst = a.get("to", "")
                if not src:
                    continue
                dest_dir = "$(BIN_DIR)/" + dst if dst else "$(BIN_DIR)"
                asset_rules.append((src, dest_dir))

        w(".PHONY: all clean install_assets")
        if asset_rules:
            w("BIN_DIR := ../../bin")
            w("all: $(FINAL_TARGET) install_assets")
        else:
            w("all: $(FINAL_TARGET)")
        w('\t@echo "✓ Built $(FINAL_TARGET) for $(UNAME_S)$(PLATFORM_TAG) ($(ARCH))"')
        w("")
        w("install_assets:")
        if asset_rules:
            for src, dest_dir in asset_rules:
                w(f"\t@mkdir -p {dest_dir}")
                w(f"\t@cp -f {src} {dest_dir}/ 2>/dev/null || true")
                w(f'\t@echo "  [assets] {src} -> {dest_dir}/"')
        else:
            w("\t@:")
        w("")

        # ON THE MAKEFILE, so a REGENERATED Makefile is a new build. The stamp
        # is keyed by platform, debug and sanitizer -- the things a caller
        # changes on the command line -- and had no way to notice the file it
        # lives in changing under it: a vendored object compiled under the old
        # rule stayed newer than its source and was linked, flags and all, into
        # a module built under the new one. ace regenerates this file whenever
        # the generator's output changes (ensure_makefile), and this is the other
        # half of that: the regeneration reaches the objects.
        w("$(BUILD_STAMP): Makefile")
        w("\t@rm -f .ace_build_*")
        w("\t@touch $@")
        w("")

        L.extend(fetch_rules)
        L.extend(build_rules)
        L.extend(obj_rules)

        # ---- hashes -------------------------------------------------------
        # Two kinds, in one generated header. The per-FILE digests below are
        # the epoch check (compareManifests, core/Bundles.h): does this module
        # agree with its loader about the contract headers. The per-REGION
        # digests appended after them are what the ABI's <Tag>_<Action>_GetHash
        # actually returns -- one SHA-256 per work/stream body, which is the
        # only way those exports can say anything about the function they are
        # named after (the macro cannot see its own body; ace_hash.py explains).
        #
        # SOURCES AS WELL AS HEADERS, because work functions live in both.
        #
        # A missing `ace` is a warning, not a build failure: the header stays
        # valid, the digests are simply absent, and every GetHash says 0 and
        # logs why (ETCS::etcs_region_hash) rather than quietly handing back
        # something that is not a content hash.
        w("ACE_HASH_REGIONS ?= ace hash regions")
        w("")
        # Makefile, for the same reason BUILD_STAMP lists it: when the RULE
        # changes -- a new kind of digest appended here, say -- an existing
        # header is newer than every source and make would keep it.
        w("$(HASH_HEADER): $(MODULE_HEADERS) $(SRC_MODULE) Makefile")
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
        w("\t@$(ACE_HASH_REGIONS) --out $@ --append $(MODULE_HEADERS) $(SRC_MODULE) \\")
        w("\t  || { echo \"[!] $(ACE_HASH_REGIONS) unavailable -- no work-region digests \\")
        w("\t            (every <Tag>_<Action>_GetHash will report 0).\"; \\")
        w("\t       echo \"// no work-region digests: ace was not on PATH at build time\" >> $@; }")
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
        w("\trm -f $(TARGET_BASE_NAME).so $(TARGET_BASE_NAME).dll $(TARGET_BASE_NAME).wasm")
        w("\trm -rf .ace_obj")
        for p in clean_paths:
            w(f"\trm -rf {p}")
        # Installed assets are this module's output too, so this module's own
        # clean is what removes them -- the most local path that knows they
        # exist. Leaving them behind means `ace make clean module X` followed
        # by a run picks up the PREVIOUS build's shaders out of bin/ and
        # reports success, which is the failure mode a clean target exists to
        # make impossible.
        #
        # Only the files this module declared, never the directory: two
        # modules may install into the same place, and one being cleaned is
        # not the other being uninstalled.
        for src, dest_dir in asset_rules:
            base = src.rsplit("/", 1)[-1]
            w(f"\trm -f {dest_dir}/{base}")
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
        # -e, not -d. A submodule checkout writes a .git FILE (a gitlink into
        # the superproject's .git/modules/...), not a directory, so a -d test
        # says "not fetched" for a tree that is fully present -- and the clone
        # it then attempts fails with "destination path already exists and is
        # not an empty directory", failing the build.
        #
        # That became reachable the moment modules/ became a submodule of its
        # own: `git submodule update --init --recursive` now checks out glfw,
        # picohttpparser, mbedtls, sqlite and CChess, and every one of them
        # hits this guard. The fetch rule and the submodule mechanism were
        # both trying to be the thing that puts vendored sources on disk;
        # -e is what lets the fetch rule notice the other one already did.
        lines.append(f"\t@if [ ! -e \"$({v}_DIR)/.git\" ]; then \\")
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

    @staticmethod
    def _dep_source_expr(v, pattern):
        """One entry of a vendor dep's `provides.sources.include`, as make sees it.

        A PATTERN GOES THROUGH $(wildcard); A NAME DOES NOT, and that is the
        whole of this function. $(wildcard) answers with what is on disk AT
        PARSE TIME, and a vendored build's own output is not there yet on the
        run that produces it -- sqlite's `sqlite3.c` is written by the
        amalgamation step this same Makefile runs. Wrapped in $(wildcard), the
        object list comes out EMPTY on a fresh tree, so the dependency is never
        compiled and never linked, and the build succeeds at doing nothing;
        run it a second time and it works, which is the shape of the bug that
        makes it so hard to see.

        Named literally, the object exists in the list before its source does,
        the order-only gate on the dep's build marker makes the source appear
        first, and one run is enough. Anything containing a glob character is
        genuinely a question about the tree and still gets asked that way.
        """
        return (f"$(wildcard $({v}_DIR)/{pattern})"
                if any(c in pattern for c in "*?[")
                else f"$({v}_DIR)/{pattern}")

    def _emit_obj_rule(self, v, dep, sources, gate=None):
        # Own flags, plus the ABI defines (these objects are linked INTO the
        # module, so they must agree with it) and the sanitizer -- these are
        # cheap to rebuild, unlike a cmake dependency, so they follow the
        # module rather than DEP_SANITIZE.
        abi = " ".join(f"-D{d}" for d in dep.get("abi_defines", []))
        cflags = " ".join(x for x in (" ".join(sources.get("cflags", [])),
                                      abi, "$(SANITIZE)", "$(DEP_TARGET_FLAGS)") if x)
        lines = []
        lines.append(f"# {dep['name']}: compiled with its own flags, not the module's")
        for ext, comp in ((".c", "$(CC)"), (".cc", "$(CXX)")):
            # BUILD_STAMP real, gates order-only: the stamp must force a
            # recompile when flags change; the gates only have to exist first.
            #
            # .ace_obj IS ONE OF THOSE GATES, rather than an mkdir inside the
            # recipe, and the difference shows up only under -j. A recipe that
            # makes its own output directory is correct exactly once: every
            # other job compiling into the same directory races it, and a
            # compiler that has already opened its temp file there fails at the
            # RENAME rather than at the open -- "unable to rename temporary
            # ... No such file or directory", which reads like a missing source
            # and is not one. As an order-only prerequisite the directory is
            # make's problem: it is created once, before any recipe that needs
            # it starts, and never again.
            gates = " | " + " ".join(list(gate or []) + [".ace_obj"])
            lines.append(f".ace_obj/{v}_%.o: $({v}_DIR)/%{ext} $(BUILD_STAMP){gates}")
            lines.append(f"\t{comp} {cflags} -c $< -o $@")
            lines.append("")
        # Order-only prerequisites are not remade when they are out of date,
        # only when they are ABSENT -- which is what a directory wants, since
        # its mtime changes every time a file lands in it.
        lines.append(".ace_obj:")
        lines.append("\t@mkdir -p $@")
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
        """Regenerate a missing OR STALE Makefile. Called on the build path.

        Generated Makefiles are gitignored, so a fresh clone has none. This is
        what makes that a non-event rather than a build failure.

        STALE MEANS: the generator, given this manifest, no longer produces the
        text that is on disk. The file is by contract a pure function of the two
        (its header says so, and generation is deterministic), so when the
        function's output changes the file is simply wrong -- and "regenerate
        only when missing" left it wrong silently. That is how a pull that
        changed the emscripten link flags built every module with the OLD flags
        and had the loader refuse all of them at registration, with nothing to
        say that the Makefile on disk was the cause. Comparing costs one
        generation per module per build, which is milliseconds.

        A module with no manifest is untouched: there is nothing to compare
        against, and such a module keeps building from whatever it has until
        someone migrates it deliberately.
        """
        if not self.has_manifest(module):
            return False
        makefile = self._module_dir(module) / "Makefile"
        if not makefile.exists():
            print(f"[*] {module}/Makefile is missing -- regenerating from manifest.")
            return self.generate_makefile(module, quiet=False)
        if self._makefile_is_current(module, makefile):
            return False
        print(f"{YELLOW}[!] {module}/Makefile is STALE -- the generator's output has "
              f"changed since it was written. Regenerating.{RESET}")
        return self.generate_makefile(module, force=True, quiet=False)

    def _makefile_is_current(self, module, makefile):
        """Does the generator reproduce the file on disk, byte for byte?"""
        try:
            m = self.load_manifest(module, resolve_pins=True, silent=True)
            return makefile.read_text() == self._emit_makefile(m)
        except Exception:
            # A manifest that will not load is generate_makefile's problem to
            # report, not this check's to guess at: leave the file alone.
            return True

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
            vendor = _vendor_union(_vendor_profiles(m, name))
            for dep in vendor:
                for d in dep.get("abi_defines", []):
                    if d not in abi:
                        abi.append(d)
            base = f"../modules/{name}"
            for dep in vendor:
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

    # Flags that pull a JS LIBRARY into the glue, as opposed to only affecting
    # codegen. The distinction is the whole point of _web_jslib_flags below: a
    # side module compiled with -sUSE_GLFW=3 gets the GLFW HEADERS and emits
    # imports for glfwCreateWindow and the rest, but -sSIDE_MODULE emits no
    # JavaScript at all, so library_glfw.js never arrives. Only the MAIN module
    # has glue, so only the main link can carry these.
    # -l<name>.js is the other spelling emscripten has for a JS library --
    # IDBFS, NODEFS, WORKERFS and their kin ship as -lidbfs.js -- and it is a
    # library the MAIN link owns for exactly the reason -sUSE_* is.
    _WEB_JSLIB_PREFIXES = ("-sUSE_", "-l")
    _WEB_JSLIB_EXACT = (
        "-sFULL_ES2", "-sFULL_ES3", "-sLEGACY_GL_EMULATION",
        "-sGL_ENABLE_GET_PROC_ADDRESS", "-sOFFSCREEN_FRAMEBUFFER",
        "-sMIN_WEBGL_VERSION", "-sMAX_WEBGL_VERSION",
    )

    def _web_jslib_flags(self, silent=False):
        """Every JS-library flag any module's Web profile asks for.

        THE FAILURE THIS PREVENTS, because it does not look like a link error.
        A -sMAIN_MODULE build needs -sERROR_ON_UNDEFINED_SYMBOLS=0 (a side
        module legitimately imports what it finds at runtime), so a symbol
        NOBODY defines is not rejected. emscripten hands the side module a lazy
        stub instead -- proxyHandler.get in the glue:

            stubs[prop] = (...args) => {
                resolved ||= resolveSymbol(prop); return resolved(...args) }

        resolveSymbol returns undefined and the program dies the first time that
        import is actually CALLED, as "TypeError: resolved is not a function",
        under doRewind/handleSleep because the call lands inside dlopen's
        asyncify rewind. Nothing in that stack names the symbol.

        A stub that is never called never throws, so the same two binaries look
        fine until a code path reaches one. Observed exactly that way: 30
        unresolved glfw* imports in WindowProvider.wasm against an etcs.js
        containing no GLFW, silent on the shell page and fatal on the window
        page, where boot.etcs calls Window.Create -> CreateWindow -> glfwInit.

        Collected from EVERY module, not only the ones a loader inherits:
        modules arrive by dlopen at runtime, so the loader cannot know which
        will show up, and a JS library that is present but unused costs glue
        size and nothing else.
        """
        flags, sources = [], {}
        mdir = self.ace_root / "modules"
        if not mdir.is_dir():
            return flags, sources
        for entry in sorted(mdir.iterdir()):
            if not (entry.is_dir() or entry.is_symlink()):
                continue
            try:
                m = self.load_manifest(entry.name, silent=True)
            except Exception:
                # A module whose manifest will not load is the module build's
                # problem to report, not the loader generator's -- and refusing
                # to emit a Makefile over it would block every other loader.
                continue
            web = m.get("build", {}).get("Web")
            if not web:
                continue
            for f in list(web.get("cxxflags", [])) + list(web.get("ldflags", [])):
                base = f.split("=")[0]
                if not (f.startswith(self._WEB_JSLIB_PREFIXES)
                        or base in self._WEB_JSLIB_EXACT):
                    continue
                if f.startswith("-l") and not f.endswith(".js"):
                    continue                         # a native library, not glue
                if f not in flags:
                    flags.append(f)
                    sources[f] = entry.name
        if flags and not silent:
            for f in flags:
                print(f"  {DIM}web jslib{RESET} {f} "
                      f"{DIM}(from {sources[f]}; the loader owns the glue){RESET}")
        return flags, sources

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

        # As in a module's Makefile: -fno-plt is an ELF flag, and emscripten's
        # clang accepts it, drops it and says so once per translation unit.
        w("PLT_FLAGS := -fno-plt")
        w("ifdef EMSCRIPTEN")
        w("  PLT_FLAGS :=")
        w("endif")
        w("")
        cxx = [f.format(std=default.get("loader", {}).get("std", "c++17"))
               for f in BASE_LOADER_CXXFLAGS]
        # The loader needs it more than any module does: the executor that
        # expands ACE_ROOT in a script statement lives in it. See ACE_ROOT_DEFINE.
        cxx.append(ACE_ROOT_DEFINE.format(root=str(self.ace_root)))
        cxx += [f"-D{d}" for d in common.get("defines", [])]
        cxx += common.get("cxxflags", [])
        cxx += ["$(DEBUGFLAGS)", "$(SANITIZE)"]
        w("CXXFLAGS := " + " \\\n            ".join(cxx))
        w("")

        exports = default.get("produces", {}).get("exports")
        # Web FIRST: under emscripten uname still reports Linux, so a Linux
        # branch above would steal the match and skip em++ / MAIN_MODULE.
        w("# Web FIRST: under emscripten uname still reports Linux.")
        w("ifdef EMSCRIPTEN")
        w("    # Loader = MAIN module. Side modules load at runtime via dylink.")
        w("    # MAIN_MODULE=1 + EXPORT_ALL so side-module GOT imports resolve.")
        w("    # -pthread / -fwasm-exceptions MUST match every side module.")
        w("    #")
        w("    # -fvisibility=hidden stays in force here too. A side module imports")
        w("    # libc/libc++ and the JS libraries from the MAIN module, which this")
        w("    # flag does not touch. What it removes from the export table is the")
        w("    # loader's own header-inline statics -- EventNode, ThreadPool,")
        w("    # MemoryArena -- so a module can only ever bind to its own copy, the")
        w("    # per-DSO grain core/ is written to. The one symbol a module dlsym()s")
        w("    # out of the loader, ETCS_GetLoaderManifest, marks itself default.")
        w("    CXX := em++")
        w("    CC  := emcc")
        w("    CXXFLAGS += -pthread -fwasm-exceptions")
        w("")
        w("    # ── MEMORY: FIXED, NOT GROWABLE, and this is the throw site ──────")
        w("    #")
        w("    # emscripten emits this ONLY for ALLOW_MEMORY_GROWTH together with")
        w("    # threads (preamble.js, #if ALLOW_MEMORY_GROWTH && PTHREADS):")
        w("    #")
        w("    #   function growMemViews() {")
        w("    #     if (wasmMemory.buffer != HEAP8.buffer) { updateMemoryViews() }")
        w("    #   }")
        w("    #")
        w("    # and calls it at the head of every JS library function that touches a")
        w("    # memory view, so each worker can re-derive its views after a grow. In")
        w("    # a pthread worker that has not yet been handed its wasmMemory, that")
        w("    # first line is `undefined.buffer` -- which is exactly the observed")
        w("    # failure, one per worker:")
        w("    #")
        w("    #   worker sent an error! etcs.js:1: TypeError: can't access")
        w("    #   property \"buffer\", wasmMemory is undefined")
        w("    #")
        w("    # With growth OFF the function is never generated, so the line cannot")
        w("    # throw. That is why this defaults to fixed rather than tuning around")
        w("    # it: it removes the failing code instead of hoping the race that")
        w("    # reaches it stops being reached.")
        w("    #")
        w("    # A -pthread build's memory is shared either way, so it needs a maximum")
        w("    # either way; with growth off emscripten uses initial as the maximum and")
        w("    # nothing more has to be said. Bump INITIAL_MEMORY if a bigger world")
        w("    # needs it -- there is no growth to fall back on now, so exhaustion is")
        w("    # an abort rather than a stall.")
        w("    #")
        w("    # 1 GB, by way of 512 MB and 256 MB. The runtime's arenas alone stood")
        w("    # at ~230 MB after a paint page booted (measured with malloc_footprint")
        w("    # from the console), which left a two-layer 1216x960 canvas -- 9 MB of")
        w("    # raster -- to be the allocation that aborted at 256. The number is not")
        w("    # about that one canvas: every scope keeps its own arena and each one")
        w("    # holds its high-water mark rather than returning pages, so the figure")
        w("    # that has to fit is the sum of the peaks, not the sum of what is live.")
        w("    # Pages are committed by the browser as they are touched, so an")
        w("    # untouched tab pays for none of it.")
        w("    ETCS_WEB_MEMORY ?= -sINITIAL_MEMORY=1073741824")
        w("")
        w("    # To go back to growth for a comparison, in one command and without")
        w("    # regenerating anything -- MAXIMUM_MEMORY is not optional in that")
        w("    # variant, because shared memory must be created with a maximum:")
        w("    #")
        w("    #   make FILE=etcs EMSCRIPTEN=1 \\")
        w("    #     ETCS_WEB_MEMORY='-sALLOW_MEMORY_GROWTH=1 -sMAXIMUM_MEMORY=1073741824'")
        w("")
        w("    # ── THE POOL: PREWARMED, AND IT DOES NOT UNDO THE DEFERRAL ───────")
        w("    #")
        w("    # PTHREAD_POOL_SIZE creates its workers during MODULE STARTUP -- before")
        w("    # main(), so before preload_web_modules opens the first side module. The")
        w("    # hazard the deferred arming exists for is a Worker starting WHILE the")
        w("    # main module is inside loadDynamicLibrary; a prewarmed pool is created")
        w("    # before that window opens, so the two fixes approach the same window")
        w("    # from opposite sides rather than cancelling out. Each worker also gets")
        w("    # its wasmMemory as part of that startup, when nothing else is in")
        w("    # flight.")
        w("    #")
        w("    # WHAT IT COSTS, because it is a trade and not a free win: every later")
        w("    # dlopen now has to be replicated into workers that already exist, which")
        w("    # is the direction emscripten's own advice warns about. With 0 it was the")
        w("    # mirror problem -- no worker to replicate into, and every worker created")
        w("    # later had to replay the whole library list by itself. Overridable for")
        w("    # exactly that reason, and worth testing SEPARATELY from the memory")
        w("    # change so a fix cannot be credited to the wrong one:")
        w("    #")
        w("    #   make FILE=etcs EMSCRIPTEN=1 ETCS_WEB_POOL='-sPTHREAD_POOL_SIZE=0'")
        w("    ETCS_WEB_POOL ?= -sPTHREAD_POOL_SIZE=0")
        w("")
        jslibs, jslib_src = self._web_jslib_flags(silent=silent)
        w("    # ── JS LIBRARIES THE SIDE MODULES WILL IMPORT ────────────────────")
        w("    #")
        w("    # Collected from every module manifest's Web profile, because only the")
        w("    # MAIN module has glue. A side module built with -sUSE_GLFW=3 gets the")
        w("    # GLFW headers and emits imports for glfwCreateWindow and the rest, but")
        w("    # -sSIDE_MODULE emits no JavaScript, so library_glfw.js never arrives")
        w("    # unless THIS link asks for it.")
        w("    #")
        w("    # And it does not fail at link time. -sERROR_ON_UNDEFINED_SYMBOLS=0 is")
        w("    # required here, so an unresolvable symbol becomes a lazy stub that")
        w("    # throws \"TypeError: resolved is not a function\" the first time it is")
        w("    # CALLED -- from inside dlopen's asyncify rewind, which looks nothing")
        w("    # like a missing function. A stub that is never called never throws, so")
        w("    # the binaries look fine until a code path reaches one: WindowProvider's")
        w("    # 30 glfw* imports were silent on the shell page and fatal on the window")
        w("    # page, where boot.etcs calls Window.Create.")
        w("    #")
        w("    # tools/wasm_link_check.py does this set difference against the built")
        w("    # binaries, which is the check ERROR_ON_UNDEFINED_SYMBOLS=0 gives up.")
        if jslibs:
            for f in jslibs:
                w(f"    #   {f}   <- {jslib_src[f]}")
        else:
            w("    #   (no module declares one)")
        w(f"    ETCS_WEB_JSLIBS ?= {' '.join(jslibs)}".rstrip())
        w("")
        w("    # ── NO -sASYNCIFY, AND IT IS NOT AVAILABLE TO THIS PROGRAM ───────")
        w("    #")
        w("    # Asyncify replaces a module's exports with JS closures, and dylink")
        w("    # stores those as the library's exports. Emscripten's cross-thread table")
        w("    # catch-up then calls addFunction(sym, sym.sig) on a closure that has no")
        w("    # .sig, dies on sig.slice, and leaves that thread's table short -- so the")
        w("    # next indirect call reports \"table index is out of bounds\". Calling")
        w("    # module functions from pool threads is what `detach` and every `->` edge")
        w("    # do, so this is the normal case, not a corner.")
        w("    #")
        w("    # Nothing here needs it: etcs_cooperative_pause_ms refuses to wait on the")
        w("    # browser's main thread instead of unwinding, and the REPL's line wait runs")
        w("    # on a Worker. dlopen remains async, driven from the page's promise chain")
        w("    # at startup rather than from inside a wasm call.")
        w("    #")
        w("    # ── STACK: 4 MiB, MAIN THREAD AND EVERY PTHREAD ───────────────────")
        w("    #")
        w("    # emscripten's default is 64 KiB, and one stream call needs well over")
        w("    # that: Entity::call keeps two MirrorBuffers (~13.8 KB each) and two")
        w("    # 4 KB transport MBuffers on ONE frame, ~36 KB before anything it")
        w("    # calls gets a byte. Exhaustion is silent in wasm -- no guard page,")
        w("    # the stack pointer walks into whatever sits below it -- and it")
        w("    # surfaced as the 'unresolved tag' and 'signature mismatch' boots that")
        w("    # only ever happened in the browser. STACK_SIZE is the main thread's;")
        w("    # DEFAULT_PTHREAD_STACK_SIZE is what pool workers and the ordering")
        w("    # threads get, and stream calls run on those. Side modules take no")
        w("    # stack flag: emcc passes -z stack-size only to a MAIN link, and a")
        w("    # side module runs on whichever thread's stack calls into it.")
        w("    #")
        w("    # This makes the stacks safe for those frames. It is NOT a fix for the")
        w("    # frame sizes, which are a defect in core/ on their own.")
        w("    LDFLAGS := -sMAIN_MODULE=1 -sEXPORT_ALL=1 -pthread -fwasm-exceptions \\")
        w("               $(ETCS_WEB_MEMORY) $(ETCS_WEB_POOL) $(ETCS_WEB_JSLIBS) \\")
        w("               -sERROR_ON_UNDEFINED_SYMBOLS=0 \\")
        w("               -sSTACK_SIZE=4MB -sDEFAULT_PTHREAD_STACK_SIZE=4MB")
        w("    # THE OUTPUT NAME, and it is not cosmetic. `-o etcs` on the web path")
        w("    # writes JAVASCRIPT to the name the NATIVE loader binary has, and")
        w("    # copy_loaders then moves it over bin/etcs -- one web build and the")
        w("    # native runtime is gone, replaced by a file the kernel cannot exec.")
        w("    # It is also what a browser is served as application/octet-stream and")
        w("    # refuses as a script, and what made every page probe two names.")
        w("    #")
        w("    # A SUFFIX, NOT AN ALIAS TARGET. The recipes below still have `etcs`")
        w("    # and `%Loader` as their targets and simply link to $@$(WEB_SUFFIX):")
        w("    # an `etcs: $(SOMETHING_ELSE)` alias with no recipe of its own hands")
        w("    # the target to make's BUILTIN link rule, which passes etcs.js to")
        w("    # wasm-ld as a link input -- `wasm-ld: error: unknown file type:")
        w("    # etcs.js`, reported against `[<builtin>: etcs]`.")
        w("    WEB_SUFFIX := .js")
        w("else ifeq ($(UNAME_S),Linux)")
        blk = default.get("build", {}).get("Linux", {})
        parts = list(blk.get("ldflags", [])) + ["-l" + l for l in blk.get("system_libs", [])]
        if exports:
            # ELF-only: audited export surface under -rdynamic (see module
            # version-script note). Loader needs this so module static-init
            # can dlsym(RTLD_DEFAULT, ETCS_GetLoaderManifest).
            parts.append(f"-Wl,--version-script={exports}")
        w(f"    LDFLAGS := {' '.join(parts)}".rstrip())
        w("else ifeq ($(UNAME_S),Windows_NT)")
        blk = default.get("build", {}).get("Win", {})
        parts = list(blk.get("ldflags", [])) + ["-l" + l for l in blk.get("system_libs", [])]
        w(f"    LDFLAGS := {' '.join(parts)}".rstrip())
        w("else")
        w("    $(error Unsupported platform: $(UNAME_S))")
        w("endif")
        w("")
        w("# Empty on every native platform, so the recipes below are byte-for-byte")
        w("# what they were: -o $@ with nothing appended.")
        w("WEB_SUFFIX ?=")
        w("")
        w("# What copy_loaders moves and what clean removes, per platform -- for the")
        w("# same reason the suffix exists. A single glob list covering both meant a")
        w("# web build moved (or a web clean deleted) bin/etcs, the NATIVE binary,")
        w("# which the web path never built and has no business touching.")
        w("ifdef EMSCRIPTEN")
        w("    LOADER_ARTIFACTS := Run_*Loader.js Run_*Loader.wasm etcs.js etcs.wasm")
        w("else")
        w("    LOADER_ARTIFACTS := Run_*Loader etcs")
        w("endif")
        w("")

        w("# Per-loader additions. EXTRA_LINK is kept OUT of LDFLAGS on purpose:")
        w("# it lands after the translation unit on the command line, because")
        w("# gold does not rescan an archive it has already passed.")
        w("#")
        w("# Bound with TARGET-SPECIFIC variables (`name: VAR += ...` below), not")
        w("# an `ifeq ($(FILE),name)` gate on a global EXTRA_CXXFLAGS/EXTRA_LINK.")
        w("# The default `loaders` target compiles every *Loader.cc in one `make`")
        w("# invocation with no FILE set, through the single shared `%Loader:")
        w("# %Loader.cc` pattern rule -- an ifeq keyed on FILE never matches there,")
        w("# so a global variable silently drops every loader's inherited flags")
        w("# except when that one loader is built alone via FILE=<name>. That is")
        w("# the exact bug _inherited_module_flags's own docstring warns about:")
        w("# the loader still compiles, quietly against /usr/include instead of")
        w("# the module's vendored headers, and fails with a signature mismatch")
        w("# in a header nobody touched. Target-specific variables are scoped to")
        w("# the target itself, so they apply whichever way that target is asked")
        w("# for -- `make loaders`, `make FILE=<name>`, or a direct `make <name>`.")
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
            if o.get("inherits_modules"):
                w(f"# {name} inherits: {', '.join(o['inherits_modules'])}")
            if extra_cxx:
                w(f"{name}: EXTRA_CXXFLAGS += {' '.join(extra_cxx)}")
            if extra_link:
                w(f"{name}: EXTRA_LINK += {' '.join(extra_link)}")
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
        w("# copy_loaders IS A PHASE, NOT A SIBLING. Listed beside the links it")
        w("# was free to run before them under -j, moving nothing and leaving")
        w("# every binary in this directory -- a build that reports success and")
        w("# populates no bin/. The links stay prerequisites, so they still")
        w("# parallelise against each other; the move waits for all of them.")
        w("all: $(LOADER_BINS) etcs")
        w("\t$(MAKE) copy_loaders")
        w("")
        w("# DECLARED PHONY ON THE WEB PATH, and it is not a tidiness thing. The")
        w("# recipe writes $@$(WEB_SUFFIX), so on the web path the target name and")
        w("# the file it produces differ -- and a NATIVE `etcs` left in this")
        w("# directory by an earlier native build is then a file make sees as the")
        w("# target, newer than etcs.cc, and it reports nothing to do. The web link")
        w("# is silently skipped and the page keeps loading the previous etcs.wasm,")
        w("# which reads as a code change that did not take effect.")
        w("ifdef EMSCRIPTEN")
        w(".PHONY: etcs $(LOADER_BINS)")
        w("endif")
        w("")
        w("# Both recipes link to $@$(WEB_SUFFIX). On a native build WEB_SUFFIX is")
        w("# empty, so the target and the file are the same name and make's own")
        w("# up-to-date check still works.")
        w("%Loader: %Loader.cc")
        w("\t$(CXX) $(CXXFLAGS) $(EXTRA_CXXFLAGS) $(EXTRADEFINES) -o Run_$@$(WEB_SUFFIX) $< "
          "$(EXTRA_LINK) $(LDFLAGS)")
        w("")
        w("etcs: etcs.cc")
        w("\t$(CXX) $(CXXFLAGS) $(EXTRA_CXXFLAGS) $(EXTRADEFINES) -o $@$(WEB_SUFFIX) $< "
          "$(EXTRA_LINK) $(LDFLAGS)")
        w("")
        w("copy_loaders:")
        w("\t@mkdir -p $(BIN_DIR)")
        w('\t@echo "--- Moving Loaders to $(BIN_DIR)/ ---"')
        w("\t@found=0; \\")
        w("\tfor f in $(LOADER_ARTIFACTS); do \\")
        w('\t    if [ -f "$$f" ]; then \\')
        w('\t        mv -f "$$f" $(BIN_DIR)/; \\')
        w('\t        echo " [✓] Moved: $$f -> $(BIN_DIR)/"; \\')
        w("\t        found=1; \\")
        w("\t    fi; \\")
        w("\tdone; \\")
        w("\tif [ $$found -eq 0 ]; then echo \" [!] No binaries found to move\"; fi")
        w("")
        w("clean:")
        w("\trm -f *.o $(LOADER_ARTIFACTS)")
        w("\t@for f in $(LOADER_ARTIFACTS); do rm -f $(BIN_DIR)/$$f; done")
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
        """Regenerate loaders/Makefile when missing or stale. Build-path hook.

        Same rule as ensure_makefile, and this is the file the rule was learned
        on: the stack size and visibility flags live in its emscripten block.
        """
        default, overrides = self._loader_manifests()
        if default is None:
            return False
        makefile = self.ace_root / "loaders" / "Makefile"
        if not makefile.exists():
            print("[*] loaders/Makefile is missing -- regenerating from manifests.")
            return self.generate_loaders_makefile()
        try:
            current = makefile.read_text() == self._emit_loaders_makefile(default, overrides)
        except Exception:
            current = True
        if current:
            return False
        print(f"{YELLOW}[!] loaders/Makefile is STALE -- the generator's output has "
              f"changed since it was written. Regenerating.{RESET}")
        return self.generate_loaders_makefile(force=True)

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
            vendor = _vendor_union(_vendor_profiles(m, module))
        except (json.JSONDecodeError, OSError, ManifestError):
            return f"  {RED}unreadable{RESET}"
        loose = [d["name"] for d in vendor
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
            # Collected as they are printed, and named again at the end: a
            # custom Makefile is the one state here that asks for a decision,
            # and the whole point is being able to find them without reading
            # every line of the listing.
            unmanaged = []
            for n in names:
                mk = self._module_dir(n) / "Makefile"
                state = self.makefile_state(mk)
                if mk.is_file() and not self._is_generated(mk): unmanaged.append(n)
                pins = self._pin_state(n)
                print(f"  {CYAN}{n:<24}{RESET} Makefile: {state}{pins}")
            defaulted = self._defaulted_modules()
            if defaulted:
                print(f"\n  {DIM}building from default.json (nothing of their "
                      f"own to declare):{RESET}")
                for n in defaulted:
                    mk = self._module_dir(n) / "Makefile"
                    state = self.makefile_state(mk)
                    if mk.is_file() and not self._is_generated(mk): unmanaged.append(n)
                    print(f"    {CYAN}{n:<22}{RESET} Makefile: {state}")
            if default is not None:
                mk = self.ace_root / "loaders" / "Makefile"
                state = self.makefile_state(mk)
                if mk.is_file() and not self._is_generated(mk): unmanaged.append("loaders")
                print(f"\n  {CYAN}{'loaders':<24}{RESET} Makefile: {state}")
                for n in sorted(overrides):
                    inh = overrides[n].get("inherits_modules", [])
                    note = f" {DIM}inherits {', '.join(inh)}{RESET}" if inh else ""
                    print(f"    {DIM}override:{RESET} {n}{note}")
            if unmanaged:
                print(f"\n  {ORANGE}custom{RESET}: {', '.join(unmanaged)}")
                print(f"  {DIM}Written by hand, not by this tool -- no build "
                      f"regenerates them and `manifest clean` leaves them "
                      f"alone. Their flags drift from every other module's "
                      f"until someone looks.{RESET}")
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
