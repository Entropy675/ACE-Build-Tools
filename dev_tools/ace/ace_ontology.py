"""ace ontology subsystem.

Owns the constraint model and nothing else: which families exist, what each
one demands, and which families a concrete leaf composes. `ace_abi` renders
this against the exported work functions; the correspondence between the two
is the point, so neither file owns both halves.

Mixed into AceManager in ace_install.py.

The model, per doc/etcs_ontology_constraint_sets.md:

  xxx.h      declares a constraint  (pure virtuals, an interface X_)
  xxxBase.h  proves it              (ETCS_DISPATCH_METHOD, a CRTP proxy)

Constraint sets are cumulative down a lineage (LocalDatabase_ : Database_
owes Database_'s methods too) and exclusive across siblings. Two families
that share no ancestor may still collide by declaring the same method name --
incidental exclusivity, discovered only when a leaf folds both.

The work-function surface is a separate axis and a NARROWER one: it bounds
what an .etcs trace may call, not what the type implements. Every constraint
method exists on every leaf that claims the family (ETCS_DISPATCH_METHOD is a
pure virtual); exporting one as a work function is the decision to let a
script call it by name.
"""
from pathlib import Path
import re

from .ace_common import (YELLOW, RED, GREEN, ORANGE, RESET, DIM)


class OntologyMixin:

    # ETCS_DISPATCH_METHOD(Ret, Name, (T, a)...) / ..._CONST
    _ONT_DISPATCH = re.compile(
        r'ETCS_DISPATCH_METHOD(?:_CONST)?\s*\(\s*[^,]+?,\s*([A-Za-z_]\w*)')
    _ONT_SUPERTYPE = re.compile(r'ETCS_SUPERTYPE_BASE\s*\(\s*([A-Za-z_]\w*)\s*\)')
    # class X_ : public Y_ / virtual public ETCS::Entity
    _ONT_IFACE = re.compile(r'^class\s+([A-Za-z_]\w*)_\s*:\s*((?:[^{;]|\n)*?)\{', re.M)
    _ONT_PARENT = re.compile(r'(?:virtual\s+)?public\s+([A-Za-z_][\w:]*)')
    _ONT_PUREVIRT = re.compile(
        r'virtual\s+[^;()]+?\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:const\s*)?=\s*0\s*;')
    # class Leaf : public ABase<Leaf>, public BBase<Leaf>
    _ONT_LEAF = re.compile(r'class\s+([A-Za-z_]\w*)\s*:\s*((?:[^{;]|\n)*?)\{', re.M)
    _ONT_BASEREF = re.compile(r'public\s+([A-Za-z_]\w*)Base\s*<')
    _ONT_TYPEDEF = re.compile(r'typedef\s+([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*;')
    _ONT_USING = re.compile(r'using\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;')

    # Vendored trees carry their own `class X : public YBase<...>` shapes that
    # are not ETCS ontology. Skipped by path rather than by guessing.
    #
    # `clay` is the first entry here that is NOT a git submodule -- it is
    # committed into the tree whole (LayoutProvider/clay). That difference is
    # invisible to this scan, which is the argument for naming directories
    # rather than testing for .git: a vendored tree is vendored because of
    # where it came from, not because of how it got here.
    _ONT_SKIP_DIRS = ("glfw", "mbedtls", "sqlite", "picohttpparser", "clay",
                      "build", "tf-psa-crypto", ".git")

    def _ontology_dir(self):
        return self.ace_root / "ontology"

    def _ont_skip(self, path):
        parts = {p.lower() for p in path.parts}
        return any(d in parts for d in self._ONT_SKIP_DIRS)

    # ---------------------------------------------------------------- families

    def _parse_ontology(self):
        """{family: {'dispatch': [...], 'parent': family|None, 'owes': [...]}}

        `owes` is the accumulated pure-virtual set from the interface lineage --
        what this family's Base must prove. Cached for the process.
        """
        if getattr(self, "_ont_cache", None) is not None:
            return self._ont_cache

        ont = self._ontology_dir()
        fams, ifaces = {}, {}
        if not ont.exists():
            self._ont_iface_cache = {}
            self._ont_cache = {}
            return self._ont_cache

        for f in sorted(ont.glob("*.h")):
            text = f.read_text(errors="ignore")
            if f.name.endswith("Base.h"):
                m = self._ONT_SUPERTYPE.search(text)
                if m:
                    fams[m.group(1)] = {
                        'dispatch': sorted(set(self._ONT_DISPATCH.findall(text))),
                        'parent': None, 'owes': [],
                    }
                continue
            for m in self._ONT_IFACE.finditer(text):
                name = m.group(1)
                parents = [p for p in self._ONT_PARENT.findall(m.group(2))
                           if not p.startswith("ETCS::")]
                ifaces[name] = {
                    'parents': [p[:-1] for p in parents if p.endswith("_")],
                    'virtuals': sorted(set(self._ONT_PUREVIRT.findall(text))),
                }

        for fam, info in fams.items():
            src = ifaces.get(fam)
            if not src:
                continue
            owed, seen, cur = [], set(), fam
            while cur and cur in ifaces and cur not in seen:
                seen.add(cur)
                owed.extend(ifaces[cur]['virtuals'])
                nxt = ifaces[cur]['parents']
                cur = nxt[0] if nxt else None
            info['owes'] = sorted(set(owed))

        # ── REFINEMENT IS DECLARED IN EITHER OF TWO PLACES ────────────────
        #
        # `class LocalDatabase_ : public Database_` states it on the interface.
        # `DrawableBase : public SurfaceBase<Derived>` states it on the Base.
        # Both mean "X refines Y", and reading only the first is what made the
        # entire Drawable lineage -- Surface, Drawable, Drawable2D, Drawable3D,
        # Camera -- read as five unrelated families sitting flat beside each
        # other.
        #
        # The second spelling is not a shortcut, it is the ONLY one available
        # to that lineage. ontology/Drawable.h has the reasoning: the supertype
        # macro inherits its interface non-virtually, so an interface that also
        # inherited its parent interface would reach it twice and every call
        # through it would be ambiguous. The rule the ontology settled on is
        #
        #     an interface declares only its own INCREMENT,
        #     a Base carries the LINEAGE
        #
        # and a model that reads only interfaces is reading the half of that
        # sentence which the Drawable family deliberately leaves empty.
        #
        # It is also the half that carries the EXCLUSIVITY. Drawable2D and
        # Drawable3D are siblings, so a leaf may hold one or the other and
        # never both -- a rule C++ already enforces (two non-virtual Drawable
        # subobjects, every call ambiguous) and this tool could not previously
        # even state, let alone check.
        for fam, info in fams.items():
            parents = []
            src = ifaces.get(fam)
            if src:
                parents.extend(p for p in src['parents'] if p != fam)
            for composed in self._base_composes(fam):
                if composed != fam and composed not in parents:
                    parents.append(composed)
            info['parents'] = parents
            # Kept singular for callers that want the primary line of descent.
            info['parent'] = parents[0] if parents else None

        self._ont_iface_cache = ifaces
        self._ont_cache = fams
        return fams

    def _base_composes(self, family):
        """The families <family>Base.h composes -- its refinement parents.

        Cached because the forest is walked repeatedly and this is a file read
        per family per walk otherwise.
        """
        cache = getattr(self, "_ont_composes_cache", None)
        if cache is None:
            cache = self._ont_composes_cache = {}
        if family in cache:
            return cache[family]
        header = self.ace_root / "ontology" / f"{family}Base.h"
        try:
            text = header.read_text(errors="ignore")
        except OSError:
            out = []               # no Base of its own composes nothing
        else:
            out = []
            for c in self._ONT_BASEREF.findall(text):
                if c not in out:
                    out.append(c)
        cache[family] = out
        return out

    def _family_parents(self, family):
        fams = self._parse_ontology()
        info = fams.get(family)
        if info is not None:
            return info.get('parents', [])
        ifaces = getattr(self, "_ont_iface_cache", {})
        src = ifaces.get(family)
        return list(src['parents']) if src else []

    def _family_children(self):
        """{parent: [child, ...]} over every family, primary parent first.

        A family with two parents (Surface refines Resizable AND Orderable --
        every surface has a size and a stacking position) is a child of both.
        The renderer expands it under the first and cross-references it under
        the rest, so the DAG is stated without being printed twice.
        """
        fams = self._parse_ontology()
        kids = {}
        for fam in sorted(fams):
            for parent in self._family_parents(fam):
                kids.setdefault(parent, []).append(fam)
        return kids

    def _family_ancestors(self, family):
        """Every family above this one, through ALL parents. The set that
        makes `related` and `owes` correct; _family_chain is the single line
        of descent used for display."""
        out, queue, seen = [], list(self._family_parents(family)), {family}
        while queue:
            cur = queue.pop(0)
            if cur in seen:
                continue
            seen.add(cur)
            out.append(cur)
            queue.extend(self._family_parents(cur))
        return out

    def _family_increment(self, family):
        """What this family adds, not what it accumulates.

        The pairing with a tree view: the shape shows the inheritance, so each
        node states only its own contribution and a reader gets the total by
        reading upward instead of by reading the same six method names at
        every depth.
        """
        fams = self._parse_ontology()
        ifaces = getattr(self, "_ont_iface_cache", {})
        own = set()
        if family in fams:
            own |= set(fams[family]['dispatch'])
        if family in ifaces:
            own |= set(ifaces[family]['virtuals'])
        for anc in self._family_ancestors(family):
            if anc in fams:
                own -= set(fams[anc]['dispatch'])
            if anc in ifaces:
                own -= set(ifaces[anc]['virtuals'])
        return sorted(own)

    def _family_chain(self, family):
        """[family, primary parent, ...] up to the Entity root -- ONE line of
        descent, for display. `_family_ancestors` is the full set.

        Walks the lineage wherever it is declared: an interface parent
        (`Database_` has no DatabaseBase.h and is still what makes
        LocalDatabase and RemoteDatabase siblings rather than strangers) or a
        Base composition (the whole Drawable lineage).
        """
        self._parse_ontology()
        chain, seen, cur = [], set(), family
        while cur and cur not in seen:
            seen.add(cur)
            chain.append(cur)
            parents = self._family_parents(cur)
            cur = parents[0] if parents else None
        return chain

    def _related_families(self, a, b):
        """True when two families share an ancestor -- siblings or a lineage.
        Their shared method names are inherited obligation (§2), not the
        incidental collision (§4) that only arises between unrelated axes."""
        ca = set(self._family_ancestors(a)) | {a}
        cb = set(self._family_ancestors(b)) | {b}
        return bool(ca & cb)

    def _family_surface(self, family):
        """Every method this family demands, its whole lineage included."""
        fams = self._parse_ontology()
        out = set()
        for link in [family] + self._family_ancestors(family):
            if link in fams:
                out |= set(fams[link]['dispatch'])
                out |= set(fams[link]['owes'])
        return sorted(out)

    def _exclusive_sets(self):
        """[(parent, [sibling, ...])] -- the branch points, §2's exclusivity.

        Two families under one parent are two specializations of the same
        constraint, so a leaf holds at most one. Only branch points with more
        than one child are exclusive of anything; a lone child constrains
        nobody.
        """
        out = []
        for parent, kids in sorted(self._family_children().items()):
            if len(kids) > 1:
                out.append((parent, sorted(kids)))
        return out

    def _exclusivity_violations(self):
        """Leaves that claim two siblings. [(module, tag, parent, [fams])]

        The check the model could not previously express. C++ already stops the
        Drawable case at compile time -- two non-virtual Drawable subobjects,
        every call through them ambiguous -- but that enforcement is a property
        of how those particular Bases happen to be written, not of the rule. A
        branch point whose Bases compose virtually would be silently claimable
        from both sides, and nothing would say so.
        """
        exclusive = self._exclusive_sets()
        if not exclusive:
            return []
        native, external = self._registered_modules()
        out = []
        for path in list(native) + list(external):
            try:
                leaves = self._parse_module_leaves(path.name)
            except Exception:
                continue           # the audit is additive; never fatal
            for tag, fams in sorted(leaves.items()):
                held = set(fams)
                for parent, kids in exclusive:
                    both = sorted(held & set(kids))
                    if len(both) > 1:
                        out.append((path.name, tag, parent, both))
        return out

    def _unproven_families(self):
        """Families whose Base does not cover what its interface lineage owes --
        a §2 violation: refinement adds obligation, it never subtracts it."""
        fams = self._parse_ontology()
        out = {}
        for fam, info in fams.items():
            proven = set()
            for link in [fam] + self._family_ancestors(fam):
                if link in fams:
                    proven |= set(fams[link]['dispatch'])
            missing = sorted(set(info['owes']) - proven)
            if missing:
                out[fam] = missing
        return out

    # ------------------------------------------------------------------ leaves

    def _parse_module_leaves(self, module):
        """{tag: [family, ...]} for one module, tags named as the ABI names them.

        A leaf reaches the ABI under its typedef alias where it has one
        (`typedef GLFWWindow Window`), otherwise under its own class name.
        """
        src = self.ace_root / "modules" / module
        if not src.exists():
            return {}

        leaves, alias = {}, {}
        for f in list(src.rglob("*.h")) + list(src.rglob("*.cc")):
            if self._ont_skip(f.relative_to(src)):
                continue
            try:
                text = f.read_text(errors="ignore")
            except OSError:
                continue
            for m in self._ONT_LEAF.finditer(text):
                bases = self._ONT_BASEREF.findall(m.group(2))
                if bases:
                    leaves[m.group(1)] = self._transitive_families(sorted(set(bases)))
            for concrete, name in self._ONT_TYPEDEF.findall(text):
                alias[concrete] = name
            for name, concrete in self._ONT_USING.findall(text):
                alias[concrete] = name

        return {alias.get(leaf, leaf): fams for leaf, fams in leaves.items()}

    def _transitive_families(self, families):
        """Expand a leaf's directly-written families through the ones their
        own Base headers compose.

        A leaf's `public XBase<Leaf>` list only names what that CLASS wrote
        down. A Base may itself compose another family AT THE FAMILY LEVEL
        (ontology/TargetBase.h composes ResizableBase, because every render
        target must handle resize -- it is not a per-backend opt-in the way
        Deletable is). Every leaf of that family then carries the composed
        family at runtime: the composed Base's own ETCS_MAKE_INSTANCE ctor
        runs as part of constructing the leaf, registering its type tag and
        interface pointer exactly as if the leaf had written the base down
        itself. Stopping at the directly-written bases under-reports what
        the tag actually answers to, which is the one thing this listing
        exists to state correctly.
        """
        out, queue, seen = [], list(families), set()
        while queue:
            fam = queue.pop(0)
            if fam in seen:
                continue
            seen.add(fam)
            out.append(fam)
            header = self.ace_root / "ontology" / f"{fam}Base.h"
            try:
                text = header.read_text(errors="ignore")
            except OSError:
                continue    # a family with no Base header of its own composes nothing
            for composed in self._ONT_BASEREF.findall(text):
                if composed not in seen:
                    queue.append(composed)
        return sorted(out)

    # ------------------------------------------------------- the correspondence

    def _constraint_report(self, tag_families, work_functions):
        """Correspondence between what a type's families demand and what it
        actually exports.

        Returns {'own': [...], 'groups': [(family, depth, [(method, exported)])],
                 'collisions': [(method, [family, family])]}.

        GROUPS ARE ORDERED AND DEPTHED BY LINEAGE, and each one carries only
        what it ADDS to the families already listed above it. A camera leaf
        holds nine families across a five-deep lineage; listing each one's full
        accumulated surface printed Blit, Clear, DrawRect and GetSize five
        times each and buried the two methods that were actually the camera's.
        The indent is the lineage, so the accumulation is read by looking up
        the column rather than by repeating it.

        `own` is every work function belonging to no constraint -- the type's
        own vocabulary, and the most specific thing about it.

        `exported` is a NAME match against the work functions, so it answers
        "can a trace line call this", not "does this type implement it" (CRTP
        already guarantees the latter) and not "is this capability reachable"
        (it may be exported under another name, or driven from C++ through an
        @rid argument).
        """
        held = list(tag_families)
        surfaces = {f: self._family_surface(f) for f in held}

        owner = {}
        collisions = {}
        for fam in sorted(surfaces):
            for meth in surfaces[fam]:
                prior = owner.get(meth)
                if prior and prior != fam and not self._related_families(prior, fam):
                    collisions.setdefault(meth, {prior}).add(fam)
                owner.setdefault(meth, fam)

        constrained = set(owner)
        exported = set(work_functions)

        # Order the families the way the lineage runs: a root the leaf holds,
        # then whatever it holds beneath it, depth-first. A family whose parent
        # the leaf does NOT hold is itself a root here -- the listing describes
        # this leaf's obligations, not the whole ontology.
        held_set = set(held)
        kids = self._family_children()
        roots = sorted(f for f in held
                       if not (set(self._family_parents(f)) & held_set))

        ordered, seen = [], set()

        def walk(fam, depth):
            if fam in seen:
                return
            seen.add(fam)
            ordered.append((fam, depth))
            for kid in sorted(kids.get(fam, [])):
                if kid in held_set:
                    # Only under its primary held parent, so a two-parent
                    # family is not listed twice.
                    primary = [p for p in self._family_parents(kid)
                               if p in held_set]
                    if primary and primary[0] != fam:
                        continue
                    walk(kid, depth + 1)

        for root in roots:
            walk(root, 0)
        for fam in sorted(held):        # anything a cycle or oddity missed
            walk(fam, 0)

        groups = []
        for fam, depth in ordered:
            covered = set()
            for anc in self._family_ancestors(fam):
                if anc in held_set:
                    covered |= set(surfaces.get(anc, ()))
            rows = [(m, m in exported) for m in surfaces[fam] if m not in covered]
            if rows:
                groups.append((fam, depth, rows))

        return {
            'own': sorted(exported - constrained),
            'groups': groups,
            'collisions': [(m, sorted(f)) for m, f in sorted(collisions.items())],
        }

    # ------------------------------------------------------------------ command

    def _family_block(self, family):
        """One family as a column block: name, lineage, then its methods.

        Used for the STANDALONE grid -- families that neither refine anything
        nor are refined, where there is no shape to draw and the whole surface
        is the increment.

        A method is RED when the family's interface lineage owes it but no
        Base in that lineage declares a dispatch for it -- ETCS_DISPATCH_METHOD
        is what expands to the pure virtual, so an owed method with no dispatch
        obliges the leaf to nothing.
        """
        fams = self._parse_ontology()
        proven = set()
        for link in [family] + self._family_ancestors(family):
            if link in fams:
                proven |= set(fams[link]['dispatch'])

        lines = [f"  {ORANGE}{family}{RESET}"]
        chain = self._family_chain(family)
        if len(chain) > 1:
            lines.append(f"    {DIM}{' <- '.join(chain[1:])} <- Entity{RESET}")

        surface = self._family_surface(family)
        if not surface:
            lines.append(f"    {DIM}(no methods){RESET}")
            return lines
        for meth in surface:
            if meth in proven:
                lines.append(f"    {meth}")
            else:
                lines.append(f"    {RED}{meth}  (no dispatch){RESET}")
        return lines

    # ------------------------------------------------------------- the forest

    def _lineage_lines(self, family, kids, expanded, prefix="", connector="",
                       via=None):
        """One family and its descendants, as tree rows.

        EACH NODE STATES ITS INCREMENT, not its accumulated surface. The shape
        already carries the accumulation -- that is the whole reason to draw it
        -- and repeating Blit/Clear/DrawRect at all five depths of the Drawable
        lineage would make the tree less informative than the flat list it
        replaces.

        A family reachable by two paths (Surface refines Resizable AND
        Orderable) is expanded the first time it is reached and shown as a
        cross-reference afterwards. Printing its subtree twice would suggest
        two families rather than one with two obligations.
        """
        fams = self._parse_ontology()
        proven = set()
        for link in [family] + self._family_ancestors(family):
            if link in fams:
                proven |= set(fams[link]['dispatch'])
        # An interface with no Base of its own obliges nobody directly -- each
        # child's Base proves the inherited set, and whether one of them fails
        # to is a fact about that child. Flagging it here would red-flag four
        # methods LocalDatabase demonstrably dispatches, on the strength of
        # RemoteDatabase not doing so.
        interface_only = family not in fams

        parents = self._family_parents(family)

        # Expanded under its FIRST parent, cross-referenced under the rest, so
        # a two-parent family (Surface refines Resizable AND Orderable) has one
        # home and the forest stays a forest.
        elsewhere = (via is not None and parents and parents[0] != via)
        if elsewhere or family in expanded:
            where = parents[0] if parents else None
            note = f"  {DIM}(shown under {where}){RESET}" if where else ""
            return [f"  {prefix}{connector}{ORANGE}{family}{RESET}{note}"]
        expanded.add(family)

        notes = []
        if len(parents) > 1:
            notes.append("also refines " + ", ".join(parents[1:]))
        siblings = [k for p in parents for k in kids.get(p, []) if k != family]
        if siblings:
            notes.append("exclusive with " + ", ".join(sorted(set(siblings))))
        if family not in fams:
            notes.append("interface only -- no Base of its own")

        note = f"   {DIM}{' -- '.join(notes)}{RESET}" if notes else ""
        lines = [f"  {prefix}{connector}{ORANGE}{family}{RESET}{note}"]

        child_prefix = prefix + ("   " if not connector else
                                 ("   " if connector.startswith("\u2514") else "\u2502  "))
        own = self._family_increment(family)
        my_kids = kids.get(family, [])
        if own:
            rail = "\u2502  " if my_kids else "   "
            for meth in own:
                token = (meth if (interface_only or meth in proven)
                         else f"{RED}{meth}  (no dispatch){RESET}")
                lines.append(f"  {child_prefix}{rail}{token}")
        elif not my_kids:
            lines.append(f"  {child_prefix}   {DIM}(no methods of its own){RESET}")

        for i, kid in enumerate(my_kids):
            last = i == len(my_kids) - 1
            # Expanded under its FIRST parent, cross-referenced under the rest,
            # so a two-parent family has one home and the tree stays a tree.
            lines.extend(self._lineage_lines(
                kid, kids, expanded, child_prefix,
                "\u2514\u2500 " if last else "\u251c\u2500 ", via=family))
        return lines

    # ------------------------------------------------------------------ command

    def ontology(self, args):
        """`ace ontology` -- the constraint surface itself, without a module.

        Two sections, because there are two shapes. Families that refine or are
        refined are drawn as a FOREST: refinement is cumulative going down and
        exclusive going across, and neither of those is legible in a flat list.
        Everything else -- an independent axis a leaf folds in on its own terms
        -- stays a column grid, which is the right rendering for a set with no
        structure to show.

        Cross-family faults do not belong in either, so they follow underneath
        as their own sections.
        """
        fams = self._parse_ontology()
        if not fams:
            print(f"  {YELLOW}No ontology/ directory under {self.ace_root}.{RESET}")
            return

        kids = self._family_children()

        # A branch point need not be a family in its own right: Database_ has
        # no DatabaseBase.h and is still what makes LocalDatabase and
        # RemoteDatabase siblings. It is a node in the forest either way --
        # dropping it would leave its two children as orphans belonging to a
        # lineage the listing never shows.
        in_tree = set()
        for parent, children in kids.items():
            in_tree.add(parent)
            in_tree.update(children)

        roots = sorted(f for f in in_tree if not self._family_parents(f))
        standalone = sorted(set(fams) - in_tree)

        print(f"\n--- ETCS Ontology ({len(fams)} famil"
              f"{'y' if len(fams) == 1 else 'ies'}: "
              f"{len(in_tree)} in {len(roots)} lineage"
              f"{'' if len(roots) == 1 else 's'}, "
              f"{len(standalone)} standalone) ---\n")

        if roots:
            print(f"  {DIM}Refinement is cumulative downward and exclusive "
                  f"across siblings. Every root sits directly under Entity; "
                  f"each node lists only what it ADDS.{RESET}\n")
            expanded = set()
            for root in roots:
                for line in self._lineage_lines(root, kids, expanded):
                    print(line)
                print()

        if standalone:
            print(f"  {DIM}Standalone -- independent axes, folded in on their "
                  f"own terms:{RESET}\n")
            blocks = [self._family_block(fam) for fam in standalone]
            for line in self._composite_columns(blocks):
                print(line)

        exclusive = self._exclusive_sets()
        if exclusive:
            print(f"  {DIM}Exclusive sets -- a leaf holds AT MOST ONE from "
                  f"each:{RESET}")
            for parent, siblings in exclusive:
                joined = " | ".join(f"{ORANGE}{s}{RESET}" for s in siblings)
                print(f"    under {ORANGE}{parent}{RESET}:  {joined}")
            print()

        violations = self._exclusivity_violations()
        if violations:
            print(f"  {RED}Leaves claiming two siblings ({len(violations)}):"
                  f"{RESET}")
            for mod, tag, parent, both in violations:
                print(f"    {mod}::{tag} holds {' + '.join(both)} "
                      f"(both under {parent})")
            print()
        elif exclusive:
            print(f"  {GREEN}No leaf in any module claims two siblings.{RESET}\n")

        unproven = self._unproven_families()
        if unproven:
            print(f"  {RED}Bases that do not prove their lineage "
                  f"({len(unproven)}):{RESET}")
            for fam, missing in sorted(unproven.items()):
                print(f"    {ORANGE}{fam}{RESET}: no dispatch for "
                      f"{', '.join(missing)}")
            print()

        # Incidental exclusivity: unrelated families sharing a name. Siblings
        # sharing one is inherited obligation, not a collision, so relatedness
        # is checked before reporting.
        by_method = {}
        for fam in fams:
            for meth in self._family_surface(fam):
                by_method.setdefault(meth, []).append(fam)

        incidental = {}
        for meth, owners in by_method.items():
            ordered = sorted(owners)
            unrelated = [(a, b) for i, a in enumerate(ordered)
                         for b in ordered[i + 1:]
                         if not self._related_families(a, b)]
            if unrelated:
                incidental[meth] = sorted({f for pair in unrelated for f in pair})

        if incidental:
            print(f"  {YELLOW}Incidental exclusivity -- unrelated families "
                  f"sharing a name, foldable only with disambiguation:{RESET}")
            for meth, fs in sorted(incidental.items()):
                joined = " + ".join(f"{ORANGE}{f}{RESET}" for f in fs)
                print(f"    {meth:<20} {joined}")
            print()
