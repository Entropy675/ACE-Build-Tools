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

from .ace_common import (YELLOW, RED, ORANGE, RESET, DIM)


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
    _ONT_SKIP_DIRS = ("glfw", "mbedtls", "sqlite", "picohttpparser",
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
            info['parent'] = src['parents'][0] if src['parents'] else None
            owed, seen, cur = [], set(), fam
            while cur and cur in ifaces and cur not in seen:
                seen.add(cur)
                owed.extend(ifaces[cur]['virtuals'])
                nxt = ifaces[cur]['parents']
                cur = nxt[0] if nxt else None
            info['owes'] = sorted(set(owed))

        self._ont_iface_cache = ifaces
        self._ont_cache = fams
        return fams

    def _family_chain(self, family):
        """[family, parent, ...] up to the Entity root.

        Walks the INTERFACE lineage, not the set of families that happen to
        have a Base: `Database_` has no DatabaseBase.h, but it is still what
        makes LocalDatabase and RemoteDatabase siblings rather than strangers.
        """
        self._parse_ontology()
        ifaces = getattr(self, "_ont_iface_cache", {})
        chain, seen, cur = [], set(), family
        while cur and cur not in seen:
            seen.add(cur)
            chain.append(cur)
            src = ifaces.get(cur)
            cur = src['parents'][0] if src and src['parents'] else None
        return chain

    def _related_families(self, a, b):
        """True when two families share an ancestor -- siblings or a lineage.
        Their shared method names are inherited obligation (§2), not the
        incidental collision (§4) that only arises between unrelated axes."""
        ca, cb = set(self._family_chain(a)), set(self._family_chain(b))
        return bool(ca & cb)

    def _family_surface(self, family):
        """Every method this family demands, its whole lineage included."""
        fams = self._parse_ontology()
        out = set()
        for link in self._family_chain(family):
            if link in fams:
                out |= set(fams[link]['dispatch'])
                out |= set(fams[link]['owes'])
        return sorted(out)

    def _unproven_families(self):
        """Families whose Base does not cover what its interface lineage owes --
        a §2 violation: refinement adds obligation, it never subtracts it."""
        fams = self._parse_ontology()
        out = {}
        for fam, info in fams.items():
            proven = set()
            for link in self._family_chain(fam):
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
                    leaves[m.group(1)] = sorted(set(bases))
            for concrete, name in self._ONT_TYPEDEF.findall(text):
                alias[concrete] = name
            for name, concrete in self._ONT_USING.findall(text):
                alias[concrete] = name

        return {alias.get(leaf, leaf): fams for leaf, fams in leaves.items()}

    # ------------------------------------------------------- the correspondence

    def _constraint_report(self, tag_families, work_functions):
        """Correspondence between what a type's families demand and what it
        actually exports.

        Returns {'own': [...], 'groups': [(family, [(method, exported)])],
                 'collisions': [(method, [family, family])]}.

        `own` is every work function belonging to no constraint -- the type's
        own vocabulary, and the most specific thing about it.

        `exported` is a NAME match against the work functions, so it answers
        "can a trace line call this", not "does this type implement it" (CRTP
        already guarantees the latter) and not "is this capability reachable"
        (it may be exported under another name, or driven from C++ through an
        @rid argument).
        """
        surfaces = {f: self._family_surface(f) for f in tag_families}

        owner = {}
        collisions = {}
        for fam, methods in surfaces.items():
            for meth in methods:
                prior = owner.get(meth)
                if prior and prior != fam and not self._related_families(prior, fam):
                    collisions.setdefault(meth, {prior}).add(fam)
                owner.setdefault(meth, fam)

        constrained = set(owner)
        exported = set(work_functions)

        groups = []
        for fam in sorted(surfaces):
            rows = [(m, m in exported) for m in surfaces[fam]]
            if rows:
                groups.append((fam, rows))

        return {
            'own': sorted(exported - constrained),
            'groups': groups,
            'collisions': [(m, sorted(f)) for m, f in sorted(collisions.items())],
        }

    # ------------------------------------------------------------------ command

    def _family_block(self, family):
        """One family as a column block: name, lineage, then its methods.

        A method is RED when the family's interface lineage owes it but no
        Base in that lineage declares a dispatch for it -- ETCS_DISPATCH_METHOD
        is what expands to the pure virtual, so an owed method with no dispatch
        obliges the leaf to nothing.
        """
        fams = self._parse_ontology()
        chain = self._family_chain(family)
        proven = set()
        for link in chain:
            if link in fams:
                proven |= set(fams[link]['dispatch'])

        lines = [f"  {ORANGE}{family}{RESET}"]
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

    def ontology(self, args):
        """`ace ontology` -- the constraint surface itself, without a module.

        Families are composited into terminal-width columns, one block each,
        the same way `ace abi` lays out tag-types: a name at the top and what
        it demands underneath. Cross-family faults do not belong in a
        per-family block, so they follow underneath as their own sections.
        """
        fams = self._parse_ontology()
        if not fams:
            print(f"  {YELLOW}No ontology/ directory under {self.ace_root}.{RESET}")
            return

        print(f"\n--- ETCS Ontology ({len(fams)} famil"
              f"{'y' if len(fams) == 1 else 'ies'}) ---\n")

        blocks = [self._family_block(fam) for fam in sorted(fams)]
        for line in self._composite_columns(blocks):
            print(line)

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
