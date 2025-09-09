import re
import requests
import shutil
import zipfile
import json
from tqdm import tqdm

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

def probe(dictionary, path, default=""):
    value = default
    first = True

    # Treat the empty path [] as a reference to .
    if not path:
        return dictionary

    for key in path:
        try:
            if first:
                value = dictionary[key]
                first = False
            else:
                value = value[key]
        # KeyError: dictionary has key accessor but not this specific key.
        # TypeError: The object is either not subscriptable or the key is not hashable.
        except (KeyError, TypeError):
            # raise ValueError(f"The path {path} is not reachable in {dictionary}")
            return default

    return value

# Download and parse CPE matches from NVD
def download_cpe_matches(basedir:str):
    print("[+] Downloading CPE matches from NVD feeds")
    r = requests.get('https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.zip', stream=True)
    with open(f"{basedir}/tmp-nvd/nvdcpematch-2.0.zip.tmp", 'wb') as f:
        pbar = tqdm(unit="B", unit_scale=True, total=int(r.headers['Content-Length']), desc='nvdcpematch-2.0.zip (tmp)')
        for chunk in r.iter_content(chunk_size=1024):
            f.write(chunk)
            pbar.update(1024)
        pbar.close()
    
    shutil.move(f"{basedir}/tmp-nvd/nvdcpematch-2.0.zip.tmp", f"{basedir}/tmp-nvd/nvdcpematch-2.0.zip")
    return

# Unzip and load CPE matches from NVD
def get_cpe_matches(basedir:str):
    print("[+] Unzipping and loading CPE matches from NVD")
    cpe_matches = {}
    try:
        cpe_matches_archive = zipfile.ZipFile(f"{basedir}/tmp-nvd/nvdcpematch-2.0.zip", 'r')
    except Exception as e:
        print("[-] CPE matches archive not found or bad format.")
        print(e)
        return cpe_matches

    for cm_file in cpe_matches_archive.namelist():
        with cpe_matches_archive.open(cm_file) as f:
            cm_data = json.load(f)
            for match_string in cm_data["matchStrings"]:
                if "matches" in match_string["matchString"].keys():
                    cpe_matches[match_string["matchString"]["matchCriteriaId"]] = match_string["matchString"]["matches"]

    return cpe_matches

# Load monitored technologies from Patrowl's Nuclei templates
def get_monitored_technologies(filename:str):
    print("[+] Loading monitored technologies from Patrowl's Nuclei templates")
    patrowl_vendors = {}
    with open(filename, 'r') as f:
        lines = f.read().splitlines()
        for line in lines:
            if not line.strip():
                continue
            vendor, product = line.split(":")
            if vendor not in patrowl_vendors:
                patrowl_vendors[vendor] = []
            patrowl_vendors[vendor].append(product)
    return patrowl_vendors

# Remove duplicated CPEs already present in the original CVE configuration
def clean_duplicated_cpes(cpe_nodes, matching_cpes):
    for node in cpe_nodes:
        if "cpe_match" in node:
            for cpe_match in node["cpe_match"]:
                if cpe_match["cpe23Uri"] in matching_cpes:
                    # Remove the CPE from the list if it is already in the node
                    matching_cpes.remove(cpe_match["cpe23Uri"])
    return matching_cpes