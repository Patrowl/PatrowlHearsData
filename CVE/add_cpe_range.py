# from packaging import version
import re
import json

CPE_MATCHES = [
    {
        "vulnerable": True,
        "cpe23Uri": "cpe:2.3:a:f5:nginx_ingress_controller:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "2.0.0",
        "versionEndIncluding": "2.4.0",
        "cpe_name": []
    },
    {
        "vulnerable": True,
        "cpe23Uri": "cpe:2.3:a:f5:nginx:*:*:*:*:open_source:*:*:*",
        "versionStartIncluding": "1.1.3",
        "versionEndIncluding": "1.22.0",
        "cpe_name": []
    },
    {
        "vulnerable": True,
        "cpe23Uri": "cpe:2.3:a:f5:nginx_ingress_controller:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "1.9.0",
        "versionEndIncluding": "1.12.4",
        "cpe_name": []
    },
    {
        "vulnerable": True,
        "cpe23Uri": "cpe:2.3:a:f5:nginx:*:*:*:*:plus:*:*:*",
        "versionStartIncluding": "r22",
        "versionEndIncluding": "r27",
        "cpe_name": []
    },
    {
        "vulnerable": True,
        "cpe23Uri": "cpe:2.3:a:f5:nginx:1.23.1:*:*:*:open_source:*:*:*",
        "cpe_name": []
    },
    {
        "vulnerable": True,
        "cpe23Uri": "cpe:2.3:a:angularjs:angular.js:*:*:*:*:*:*:*:*",
        "versionEndExcluding": "1.7.9",
        "cpe_name": []
    }
]

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

def load_cpes_from_files(file_paths: list) -> list:
    print("Loading CPEs from files...")
    cpe_list = {}
    for file_path in file_paths:
        with open(file_path, 'r') as f:
            cpe_list.update(json.load(f)["cpes"])
            # cpes = json.load(f)["cpes"]
            # print(cpes)
    return cpe_list

def get_cpe_versions(cpe_list: dict, vendor: str, product: str) -> list:
    cpes = cpe_list[vendor][product].keys()

    cpe_versions = {}
    # Ex: {'r22': ['cpe:2.3:a:f5:nginx:r22:*:*:*:plus:*:*:*'], 'r27': ['cpe:2.3:a:f5:nginx:r27:*:*:*:plus:*:*:*']}
    for cpe in cpes:
        cpe_version = cpe.split(":")[5]
        if cpe_version not in cpe_versions:
            cpe_versions[cpe_version] = [cpe]
        else:
            cpe_versions[cpe_version].append(cpe)

    return cpe_versions


CPE_LIST = load_cpes_from_files(
    [
        "/Users/makyotox/Projects/PatrowlHearsData/CPE/data/cpes.json",
        "/Users/makyotox/Projects/PatrowlHearsData/CPE/data/cpes-diff.json",
    ]
)

# cpes = cpe_list["f5"]["nginx"].keys()

# cpe_versions = {}
# # Ex: {'r22': ['cpe:2.3:a:f5:nginx:r22:*:*:*:plus:*:*:*'], 'r27': ['cpe:2.3:a:f5:nginx:r27:*:*:*:plus:*:*:*']}
# for cpe in cpes:
#     cpe_version = cpe.split(":")[5]
#     if cpe_version not in cpe_versions:
#         cpe_versions[cpe_version] = [cpe]
#     else:
#         cpe_versions[cpe_version].append(cpe)
#     # cpe_versions.update({cpe_version: cpe})
# # print(cpe_versions)

for cpe_match in CPE_MATCHES:
    if not cpe_match["vulnerable"]:
        continue

    cpes_matched = []
    # List available CPE for this vendor/product
    print(f"Checking CPE matches for {cpe_match['cpe23Uri']}...")
    vendor = cpe_match['cpe23Uri'].split(":")[3]
    product = cpe_match['cpe23Uri'].split(":")[4]
    cpe_versions = get_cpe_versions(CPE_LIST, vendor, product)

    # For CVE before 2024
    if "versionStartIncluding" in cpe_match and "versionEndIncluding" in cpe_match:
        for version, cpes in cpe_versions.items():
            # print(f"Version: {version}, CPEs: {cpes}")

            # print(f"Checking if version {cpe_match['versionStartIncluding']} to {cpe_match['versionEndIncluding']} "
            #     f"includes the candidate version '{version}'...")

            res = check_version_between(version, cpe_match["versionStartIncluding"], cpe_match["versionEndIncluding"])
            # print(res)
            if res:
                cpes_matched.extend(cpes)

        print(f"Matched CPEs for {cpe_match['cpe23Uri']} (between {cpe_match['versionStartIncluding']} and {cpe_match['versionEndIncluding']}): {cpes_matched}")

    if "versionEndExcluding" in cpe_match:
        for version, cpes in cpe_versions.items():
            print(version, cpes)
            # if version in cpe_match["versions"]:
            #     cpes_matched.extend(cpes)
            
            res = check_version_between(version, "0", cpe_match["versionEndExcluding"])
            # print(res)
            if res:
                cpes_matched.extend(cpes)

        print(f"Matched CPEs for {cpe_match['cpe23Uri']} (before {cpe_match['versionEndExcluding']}): {cpes_matched}")
