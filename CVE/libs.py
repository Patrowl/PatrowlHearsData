import re

PREFIX_NUM_RE = re.compile(r"^([A-Za-z]+)(\d+)$")
NUMERIC_VER_RE = re.compile(r"^\d+(?:\.\d+)*$")

def parse_prefixed_num(s: str):
    m = PREFIX_NUM_RE.match(s)
    if not m:
        return None
    prefix, num = m.group(1).lower(), int(m.group(2))
    return prefix, num

def parse_numeric_ver(s: str):
    if not NUMERIC_VER_RE.match(s):
        return None
    return tuple(int(x) for x in s.split("."))

def cmp_tuples(a, b):
    # Compare tuples of possibly different lengths by padding with zeros
    maxlen = max(len(a), len(b))
    a_pad = a + (0,) * (maxlen - len(a))
    b_pad = b + (0,) * (maxlen - len(b))
    return (a_pad > b_pad) - (a_pad < b_pad)

def is_between(min_v, cand_v, max_v):
    return cmp_tuples(min_v, cand_v) <= 0 and cmp_tuples(cand_v, max_v) <= 0


def check_version_between(input_version: str, min_version: str, max_version: str) -> bool:
    min_pref = parse_prefixed_num(min_version)
    cand_pref = parse_prefixed_num(input_version)
    max_pref = parse_prefixed_num(max_version)

    if all(v is not None for v in (min_pref, cand_pref, max_pref)):
        min_prefix, min_num = min_pref
        cand_prefix, cand_num = cand_pref
        max_prefix, max_num = max_pref

        if not (min_prefix == cand_prefix == max_prefix):
            # print("Error: Prefixed versions must share the same prefix (case-insensitive).")
            return False

        in_range = min_num <= cand_num <= max_num
        # print("✅ within range (pn)" if in_range else "❌ out of range (pn)")
        return True if in_range else False

    # Fallback to dotted numeric versions (semantic-ish without extras)
    min_numv = parse_numeric_ver(min_version)
    cand_numv = parse_numeric_ver(input_version)
    max_numv = parse_numeric_ver(max_version)

    if all(v is not None for v in (min_numv, cand_numv, max_numv)):
        in_range = is_between(min_numv, cand_numv, max_numv)
        # print("✅ within range (pv)" if in_range else "❌ out of range (pv)")
        return True if in_range else False

    # Mixed or unsupported formats
    # print("❌ out of rang (default)")
    return False