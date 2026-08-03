MAX_ARITY = 64
OUTPUT_FILE = "AirtyMacros_Generated.h"
GUARD = "AIRTYMACROS_GENERATED_H__"

def fe_block(prefix, n, comma=False, fixed=False):
    lines = []
    sep = "," if comma else ""
    if fixed:
        lines.append(f"#define {prefix}_1(m, f, x)  m(f, x)")
        for i in range(2, n + 1):
            lines.append(f"#define {prefix}_{i}(m, f, x, ...)  m(f, x) {prefix}_{i-1}(m, f, __VA_ARGS__)")
    else:
        lines.append(f"#define {prefix}_1(m, x)  m(x)")
        for i in range(2, n + 1):
            lines.append(f"#define {prefix}_{i}(m, x, ...)  m(x){sep} {prefix}_{i-1}(m, __VA_ARGS__)")
    return lines

def numbered_params(n):
    return ",".join(f"_{i}" for i in range(1, n + 1))

def get_macro_block(name, n):
    return f"#define {name}({numbered_params(n)},NAME,...) NAME"

def for_each_block(name, get_macro_name, prefix, n, fixed=False):
    fe_list = ",".join(f"{prefix}_{i}" for i in range(n, 0, -1))
    if fixed:
        return (f"#define {name}(action, fixed, ...) \\\n"
                f"  {get_macro_name}(__VA_ARGS__,{fe_list})(action, fixed, __VA_ARGS__)")
    return (f"#define {name}(action,...) \\\n"
            f"  {get_macro_name}(__VA_ARGS__,{fe_list})(action,__VA_ARGS__)")

def dispatch_select_block(n):
    # The previous version of this block relied on GNU's `, ##__VA_ARGS__`
    # comma-elision extension to distinguish "truly zero real arguments"
    # from "one empty argument". That extension is only active under GNU
    # dialect flags (-std=gnu++17); under strict ISO dialect (-std=c++17 --
    # what this project's actual build command uses), GCC/Clang silently
    # do NOT elide the comma, which shifts every position in the selector
    # by one and makes EVERY call -- zero-arg included -- resolve to the
    # nonzero ("N") branch. That's the exact bug that broke Ephemeral_'s
    # zero-arg Reset()/IsActive() dispatch.
    #
    # This version detects emptiness with the standard portable "IS_EMPTY"
    # idiom (Gustedt-style: probe via forced-paren triggering + has-comma
    # checks), which works identically under strict ISO C++ with no
    # reliance on any GNU-specific comma-pasting behavior. Verified against
    # zero-arg, single-arg, and multi-(Type,name)-tuple-arg cases under
    # `-std=c++17 -fpermissive` (this project's real build flags) before
    # being folded in here.
    has_comma_params = ",".join(f"_{i}" for i in range(0, 16))
    has_comma_fillers = ",".join(["1"] * 15)
    lines = []
    lines.append("// Self-contained concat helper -- identical in body to ETCS_API.h's own")
    lines.append("// ETCS_DISPATCH_CONCAT2/_ (redefining with an IDENTICAL token sequence is")
    lines.append("// not an error), so this block doesn't depend on include order elsewhere.")
    lines.append("#define ETCS_DISPATCH_CONCAT2_(a,b)   a##b")
    lines.append("#define ETCS_DISPATCH_CONCAT2(a,b)    ETCS_DISPATCH_CONCAT2_(a,b)")
    lines.append(f"#define ETCS_DISPATCH_ARG16_({has_comma_params},N,...) N")
    lines.append(f"#define ETCS_DISPATCH_HAS_COMMA(...) ETCS_DISPATCH_ARG16_(__VA_ARGS__,{has_comma_fillers},0)")
    lines.append("#define ETCS_DISPATCH_TRIGGER_PAREN_(...) ,")
    lines.append("#define ETCS_DISPATCH_PASTE5_(a,b,c,d,e) a##b##c##d##e")
    lines.append("#define ETCS_DISPATCH_PASTE5(a,b,c,d,e) ETCS_DISPATCH_PASTE5_(a,b,c,d,e)")
    lines.append("#define ETCS_DISPATCH_IS_EMPTY_CASE_0001 ,")
    lines.append("#define ETCS_DISPATCH_ISEMPTY_(_0,_1,_2,_3) \\")
    lines.append("    ETCS_DISPATCH_HAS_COMMA(ETCS_DISPATCH_PASTE5(ETCS_DISPATCH_IS_EMPTY_CASE_, _0, _1, _2, _3))")
    lines.append("#define ETCS_DISPATCH_ISEMPTY(...) \\")
    lines.append("    ETCS_DISPATCH_ISEMPTY_( \\")
    lines.append("        ETCS_DISPATCH_HAS_COMMA(__VA_ARGS__), \\")
    lines.append("        ETCS_DISPATCH_HAS_COMMA(ETCS_DISPATCH_TRIGGER_PAREN_ __VA_ARGS__), \\")
    lines.append("        ETCS_DISPATCH_HAS_COMMA(__VA_ARGS__ (~)), \\")
    lines.append("        ETCS_DISPATCH_HAS_COMMA(ETCS_DISPATCH_TRIGGER_PAREN_ __VA_ARGS__ (~)) \\")
    lines.append("    )")
    lines.append("#define ETCS_DISPATCH_SELECT_IF_0(t, f) f")
    lines.append("#define ETCS_DISPATCH_SELECT_IF_1(t, f) t")
    lines.append("#define ETCS_DISPATCH_SELECT_IF_(cond, t, f) ETCS_DISPATCH_CONCAT2(ETCS_DISPATCH_SELECT_IF_, cond)(t, f)")
    lines.append("#define ETCS_DISPATCH_SELECT_IF(cond, t, f)  ETCS_DISPATCH_SELECT_IF_(cond, t, f)")
    lines.append("#define ETCS_DISPATCH_SELECT(...) \\")
    lines.append("    ETCS_DISPATCH_SELECT_IF(ETCS_DISPATCH_ISEMPTY(__VA_ARGS__), 0, N)")
    return lines

def generate(n):
    out = []
    out.append(f"#ifndef {GUARD}")
    out.append(f"#define {GUARD}")
    out.append(f"// --- Macro Expansion Helpers (arity {n}) ---")
    out.extend(fe_block("FE", n))
    out.append("#define BRACKET_UNWRAP(...) __VA_ARGS__")
    out.append(get_macro_block("GET_MACRO", n))
    out.append(for_each_block("FOR_EACH", "GET_MACRO", "FE", n))
    out.append(f"// --- Fixed-Argument Expansion Helpers (arity {n}) ---")
    out.extend(fe_block("FE_FIXED", n, fixed=True))
    out.append(get_macro_block("GET_MACRO_FIXED", n))
    out.append(for_each_block("FOR_EACH_FIXED", "GET_MACRO_FIXED", "FE_FIXED", n, fixed=True))
    out.append(f"// --- Comma-joining variant (arity {n}) ---")
    out.extend(fe_block("FE_C", n, comma=True))
    out.append(get_macro_block("GET_MACRO_C", n))
    out.append(for_each_block("FOR_EACH_COMMA", "GET_MACRO_C", "FE_C", n))
    out.append(f"// --- ETCS_DISPATCH_SELECT (arity {n}) ---")
    out.extend(dispatch_select_block(n))
    out.append(f"#endif // {GUARD}")
    return "\n".join(out) + "\n"

if __name__ == "__main__":
    content = generate(MAX_ARITY)
    with open(OUTPUT_FILE, "w") as f:
        f.write(content)
    print(f"Wrote {OUTPUT_FILE} ({content.count(chr(10))} lines, MAX_ARITY={MAX_ARITY})")
