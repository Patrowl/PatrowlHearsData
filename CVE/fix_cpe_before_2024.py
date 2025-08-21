from collections import Counter
from datetime import datetime, timedelta
import requests
import os
import zipfile
import json
from tqdm import tqdm
from libs import check_version_between
BASEDIR = os.path.dirname(os.path.realpath(__file__))
NUCLEI_VENDORS_FILE = os.path.join(BASEDIR, "nuclei_vendors.txt")
CPE_DICT = {}


def same_items_unordered(a, b) -> bool:
    """True if a and b contain the same items with the same multiplicities."""
    return Counter(a) == Counter(b)

def query_all(data, **criteria):
    """Return items where ALL key=value pairs match exactly."""
    # return [item for item in data if all(item.get(k) == v for k, v in criteria.items())]
    results = []
    for item in data:
        all_match = True
        for k, v in criteria.items():
            if k == "cpe23Uri":
                v = ":".join(v.split(":")[:6])
                if item.get(k).startswith(v):
                    all_match = False
                    break  # stop checking this item
            else:
                if item.get(k) != v:
                    all_match = False
                    break  # stop checking this item
        if all_match:
            results.append(item)
    return results

def get_matching_cpes(**criterias):
    """Return a list of matching CPEs based on the given criteria."""
    matching_cpes = query_all(CPE_DICT, **criterias)
    # criterias = list(criterias.keys())
    # criterias.append("cpe_name")
    matching_cpes_list = []
    if len(matching_cpes) > 0:
        criterias = list(criterias.keys())
        criterias.append("cpe_name")
        for matching_cpe in matching_cpes:
            # Ensure all criteria are strictly met
            if same_items_unordered(criterias, matching_cpe.keys()):
                # print(f"Matching CPE: {matching_cpe['cpe_name']}")
                for mcpe in matching_cpe['cpe_name']:
                    matching_cpes_list.append(mcpe["cpe23Uri"])

    return matching_cpes_list

def clean_cpes():
    """Clean and organize CPEs from Nuclei templates into a structured format."""
    cleaned_cpes = {}
    for cpe in CPE_DICT:
        vendor = cpe['cpe23Uri'].split(":")[3]
        product = cpe['cpe23Uri'].split(":")[4]
        if vendor not in cleaned_cpes:
            cleaned_cpes[vendor] = {}
        if product not in cleaned_cpes[vendor]:
            cleaned_cpes[vendor][product] = []

        for cpe_name in cpe['cpe_name']:
            cleaned_cpes[vendor][product].append(cpe_name["cpe23Uri"])

    for vendor in cleaned_cpes:
        for product in cleaned_cpes[vendor]:
            # Keep only the first CPE for each vendor:product pair
            cleaned_cpes[vendor][product] = sorted(set(cleaned_cpes[vendor][product]))
    return cleaned_cpes

def search_missing_cpes(cpe_dict_clean, vendor, product, **criteria):
    """Search for CPEs that match the criteria but are not referenced in the official mapping."""
    results = []
    if vendor in cpe_dict_clean.keys() and product in cpe_dict_clean[vendor].keys():
        min_version = criteria.get("versionStartIncluding", "")
        if min_version == "":
            min_version = criteria.get("versionStartExcluding", "0")
        max_version = criteria.get("versionEndIncluding", "")
        if max_version == "":
            max_version = criteria.get("versionEndExcluding", "999999")
        for cpe in cpe_dict_clean[vendor][product]:
            cpe_version = cpe.split(":")[5]
            if check_version_between(cpe_version, min_version, max_version):
                results.append(cpe)
    return results

def clean_duplicated_cpes(cpe_nodes, matching_cpes):
    """Remove CPEs from the matching list if they are already in the original CVE."""
    for node in cpe_nodes:
        if "cpe_match" in node:
            for cpe_match in node["cpe_match"]:
                if cpe_match["cpe23Uri"] in matching_cpes:
                    # Remove the CPE from the list if it is already in the node
                    matching_cpes.remove(cpe_match["cpe23Uri"])
    return matching_cpes

print("[+] Loading vendor:product files from Patrowl & Nuclei templates")
patrowl_vendors = {}
with open(NUCLEI_VENDORS_FILE, 'r') as f:
    lines = f.read().splitlines()
    for line in lines:
        if not line.strip():
            continue
        vendor, product = line.split(":")
        if vendor not in patrowl_vendors:
            patrowl_vendors[vendor] = []
        patrowl_vendors[vendor].append(product)

if not os.path.exists(BASEDIR+'/tmp-nvd/'):
    os.makedirs(BASEDIR+'/tmp-nvd/')

# print("[+] Downloading CVE dictionary from NVD feeds")
# r = requests.get('https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip', stream=True)
# with open(f"{BASEDIR}/tmp-nvd/nvdcpematch-1.0.json.zip", 'wb') as f:
#     pbar = tqdm(unit="B", unit_scale=True, total=int(r.headers['Content-Length']), desc="nvdcpematch-1.0.json.zip")
#     for chunk in r.iter_content(chunk_size=1024):
#         f.write(chunk)
#         pbar.update(1024)
#     pbar.close()

print("[+] Unzipping and loading CPE dictionary from NVD")
archive = zipfile.ZipFile(f"{BASEDIR}/tmp-nvd/nvdcpematch-1.0.json.zip", 'r')
jsonfile = archive.open(archive.namelist()[0])
CPE_DICT = json.loads(jsonfile.read())["matches"]

print("[+] Search and store CPE list by vendor + product")
cpe_dict_clean = clean_cpes()

# Prepare CVE listing
cves_dir = os.path.join(BASEDIR, "data/")
cve_files = []

# Look for CVE candidates
for year_dir in sorted(os.listdir(cves_dir)):
    # if year_dir in ["2025", "2024"]:
    #     continue
    if year_dir not in ["2022"]:
        continue

    year_dir_path = os.path.join(cves_dir, year_dir)
    if os.path.isdir(year_dir_path) is False:
        continue

    for cve_file in sorted(os.listdir(year_dir_path)):
        cve_file_path = os.path.join(year_dir_path, cve_file)
        # if cve_file == "CVE-2022-41741.json":
        cve_files.append(cve_file_path)

nb_matches = 0
pbar = tqdm(cve_files)
for cve_file in pbar:
    # print(cve_file)
    matching_cpes = []
    cpe_nodes = {}
    with open(cve_file, 'r') as inputfile:
        file_content = json.load(inputfile)
        cpe_nodes = file_content["configurations"]["nodes"]
        for node in cpe_nodes:
            if "cpe_match" in node:
                cpe_matches = node["cpe_match"]
                cpe_matches_extended = []
                # Do something with the CPE matches
                for cpe_match in cpe_matches:
                    if not cpe_match["vulnerable"]:
                        continue

                    # List available CPE for this vendor/product
                    # print(f"Checking CPE matches for {cpe_match['cpe23Uri']}...")
                    vendor = cpe_match['cpe23Uri'].split(":")[3]
                    product = cpe_match['cpe23Uri'].split(":")[4]

                    if vendor in patrowl_vendors and product in patrowl_vendors[vendor]:
                        cpe_match.pop("vulnerable", None)
                        cpe_match.pop("cpe_name", None)

                        if len(cpe_match.keys()) <= 1: # break loop if extra criteria like "versionEndIncluding"
                            continue
                        new_matching_cpes = get_matching_cpes(**cpe_match)
                        if len(new_matching_cpes) > 0:
                            # print(f"Found CPEs for {cpe_match['cpe23Uri']}: {new_matching_cpes}")
                            matching_cpes.extend(new_matching_cpes)
                            continue
                        
                        # print(f"No matching CPE found for {cpe_match['cpe23Uri']} with criteria {cpe_match}")
                        # Try to find missing pieces
                        new_matching_cpes = search_missing_cpes(cpe_dict_clean, vendor, product, **cpe_match)
                        if len(new_matching_cpes) > 0:
                            # print(f"Found missing CPEs for {cpe_match['cpe23Uri']}: {new_matching_cpes}")
                            matching_cpes.extend(new_matching_cpes)

    # print(matching_cpes)
    # Check if updates have been found and update CVE file
    if len(matching_cpes) > 0:
        matching_cpes = sorted(set(matching_cpes))  # Remove duplicates
        matching_cpes = clean_duplicated_cpes(cpe_nodes, matching_cpes)
        # print(cve_file, "=>", matching_cpes)
        new_node = {
            "operator": "OR",
            "children": [],
            "cpe_match": []
        }
        for cpe in matching_cpes:
            new_node["cpe_match"].append({
                "vulnerable": True,
                "cpe23Uri": cpe,
                "cpe_name": []
            })

        new_file_content = {}
        with open(cve_file, 'r') as inputfile:
            new_file_content = json.load(inputfile)
            new_file_content["configurations"]["nodes"].append(new_node)
            new_file_content["lastModifiedDate"] = datetime.now().strftime("%Y-%m-%dT%H:%MZ")
            # print(f"New node created for {cve_file}: {new_node}")
            # print(f"Updated file content for {cve_file}: {new_file_content}")

        with open(cve_file, "w") as f:
            json.dump(new_file_content, f)
    
    nb_matches += len(matching_cpes)
    pbar.set_description("Matching CPEs: %i" % nb_matches)
