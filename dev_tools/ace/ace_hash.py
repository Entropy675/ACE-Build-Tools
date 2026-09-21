"""ace_hash.py — the source-region digests a module's ABI hands out.

    ace hash regions --out module_hashes.h [--append] <sources...>

WHAT A REGION IS. The span of source from a work function's macro name through
the closing brace of the body written under it:

    DEFINE_WORK_FUNC(PaintDocument, ImportImage)
    {
        ...
    }                                   <-- region ends here, inclusive

SHA-256 of exactly those bytes, emitted as a registration into the module's own
table (ETCS::etcs_register_region_digest, core/Entity.h). The ABI's
<Tag>_<Action>_GetHash hands out the first 64 bits of it; a tag composes over
its actions' digests and a module over its tags, so an edit to one body moves
one leaf and its ancestors and nothing else.

WHY THE BUILD COMPUTES IT. The macro cannot: DEFINE_WORK_FUNC takes the type
and the action, and the body is written AFTER the macro's own invocation, so
the preprocessor never sees it as an argument and cannot stringify it. Nothing
inside the language can read those bytes. The build step that already hashes
every header is the one place that has them.

RAW BYTES, comments and whitespace included -- the same bargain the header
hashes in the same file already make. A reformat reads as a change. This is a
content hash of a region, not a semantic hash of behaviour.
"""

import hashlib
import os
import sys

# The macros that introduce a dispatchable body. Each takes (Type, Name) as its
# first two arguments; _TYPED takes parameter groups after them, which are part
# of the region because they are part of the signature the boundary calls.
REGION_MACROS = (
    "DEFINE_WORK_FUNC_TYPED",
    "DEFINE_WORK_FUNC",
    "DEFINE_STREAM_FUNC_PRODUCE",
    "DEFINE_STREAM_FUNC_CONSUME",
)

_IDENT = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def _code_mask(text):
    """True at every byte that is CODE -- not a comment, not inside a literal.

    A macro name inside a comment is prose, and a brace inside a string is not
    a brace. Both appear in this tree (the headers are mostly comment), so the
    scan below runs against this mask rather than against the raw text.
    """
    n = len(text)
    mask = bytearray(b"\x01") * n
    i = 0
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                mask[i] = 0
                i += 1
        elif c == "/" and nxt == "*":
            mask[i] = mask[i + 1] = 0
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                mask[i] = 0
                i += 1
            if i < n:
                mask[i] = 0
                if i + 1 < n:
                    mask[i + 1] = 0
                i += 2
        elif c == 'R' and nxt == '"':
            # Raw string: R"delim( ... )delim"
            j = text.find("(", i + 2)
            if j == -1:
                i += 1
                continue
            delim = text[i + 2:j]
            end = text.find(")" + delim + '"', j)
            end = n if end == -1 else end + len(delim) + 2
            for k in range(i, min(end, n)):
                mask[k] = 0
            i = end
        elif c == '"' or c == "'":
            quote = c
            mask[i] = 0
            i += 1
            while i < n:
                if text[i] == "\\":
                    mask[i] = 0
                    if i + 1 < n:
                        mask[i + 1] = 0
                    i += 2
                    continue
                mask[i] = 0
                if text[i] == quote:
                    i += 1
                    break
                i += 1
        else:
            i += 1
    return mask


def _skip_ws(text, mask, i):
    n = len(text)
    while i < n and (text[i].isspace() or not mask[i]):
        i += 1
    return i


def _match_pair(text, mask, i, open_ch, close_ch):
    """Index just past the `close_ch` that closes the `open_ch` at i, or -1."""
    if i >= len(text) or text[i] != open_ch:
        return -1
    depth = 0
    n = len(text)
    while i < n:
        if mask[i]:
            if text[i] == open_ch:
                depth += 1
            elif text[i] == close_ch:
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return -1


def scan_regions(text):
    """[(key, start, end)] for every work/stream body in one source file."""
    mask = _code_mask(text)
    out = []
    for macro in REGION_MACROS:
        start = 0
        while True:
            at = text.find(macro, start)
            if at == -1:
                break
            start = at + len(macro)
            if not mask[at]:
                continue
            # A whole token: DEFINE_WORK_FUNC must not match inside
            # DEFINE_WORK_FUNC_TYPED (which is why the longer name is tried
            # first, but the boundary check is what actually decides).
            if at > 0 and text[at - 1] in _IDENT:
                continue
            after = at + len(macro)
            if after < len(text) and text[after] in _IDENT:
                continue
            paren = _skip_ws(text, mask, after)
            close = _match_pair(text, mask, paren, "(", ")")
            if close == -1:
                continue
            args = text[paren + 1:close - 1]
            depth = 0
            first = []
            head = []
            for ch in args:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                if ch == "," and depth == 0:
                    head.append("".join(first).strip())
                    first = []
                    if len(head) == 2:
                        break
                    continue
                first.append(ch)
            if len(head) < 2:
                head.append("".join(first).strip())
            if len(head) < 2 or not head[0] or not head[1]:
                continue
            body = _skip_ws(text, mask, close)
            if body >= len(text) or text[body] != "{":
                # A declaration rather than a definition (the macro is also
                # used to forward-declare in a couple of places). No body, no
                # region.
                continue
            end = _match_pair(text, mask, body, "{", "}")
            if end == -1:
                continue
            out.append(("%s.%s" % (head[0], head[1]), at, end))
    return out


def digest_regions(paths):
    """{key: hexdigest} over every source given, in a path-stable order.

    A key defined more than once -- the same action in a Win/ header and a
    Linux/ one -- hashes over ALL of its definitions, in sorted path order.
    That is the same rule the module header hashes follow (every platform's
    headers, so one commit attests identically on every OS), and for the same
    reason: a digest that depended on which platform was built could not be
    compared across two builds of the same source.
    """
    found = {}
    for path in sorted(paths):
        try:
            with open(path, "r", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        for key, start, end in scan_regions(text):
            found.setdefault(key, []).append(text[start:end])
    return {k: hashlib.sha256("".join(v).encode("utf-8")).hexdigest()
            for k, v in found.items()}


class HashMixin:
    """`ace hash regions`."""

    def hash(self, args):
        if not args or args[0] != "regions":
            print("    Usage: ace hash regions --out <header.h> [--append] <sources...>")
            return 1
        rest = args[1:]
        out = None
        append = False
        sources = []
        i = 0
        while i < len(rest):
            a = rest[i]
            if a == "--out" and i + 1 < len(rest):
                out = rest[i + 1]
                i += 2
            elif a == "--append":
                append = True
                i += 1
            else:
                sources.append(a)
                i += 1
        if not out or not sources:
            print("    Usage: ace hash regions --out <header.h> [--append] <sources...>")
            return 1

        digests = digest_regions(sources)
        lines = ["// Work/stream source-region digests -- generated, do not edit.",
                 "// %d region(s); see `ace hash regions` (dev_tools/ace/ace_hash.py)."
                 % len(digests)]
        for key in sorted(digests):
            var = key.replace(".", "_")
            lines.append(
                'inline const bool _reg_region_%s = '
                'ETCS::etcs_register_region_digest("%s", "%s");' % (var, key, digests[key]))
        body = "\n".join(lines) + "\n"
        with open(out, "a" if append else "w") as f:
            f.write(body)
        print("[*] %s: %d work/stream region digest(s) -> %s"
              % (os.path.basename(os.path.dirname(os.path.abspath(out))) or "module",
                 len(digests), out))
        return 0


if __name__ == "__main__":
    sys.exit(HashMixin().hash(sys.argv[1:]))
