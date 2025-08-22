import argparse
from collections import Counter
from datetime import datetime
import requests
import os
import zipfile
import json
from tqdm import tqdm
from libs import check_version_between
BASEDIR = os.path.dirname(os.path.realpath(__file__))
NUCLEI_VENDORS_FILE = os.path.join(BASEDIR, "nuclei_vendors.txt")
CPE_DICT = {}

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

def clean_duplicated_cpes(cpe_nodes, matching_cpes):
    """Remove CPEs from the matching list if they are already in the original CVE."""
    for node in cpe_nodes:
        if "cpe_match" in node:
            for cpe_match in node["cpe_match"]:
                if cpe_match["cpe23Uri"] in matching_cpes:
                    # Remove the CPE from the list if it is already in the node
                    matching_cpes.remove(cpe_match["cpe23Uri"])
    return matching_cpes


def main():
    global CPE_DICT
    global BASEDIR
    cpe_criterias = ["versionEndExcluding", "versionEndIncluding", "versionStartExcluding", "versionStartIncluding"]
    # Create argument parser
    parser = argparse.ArgumentParser(description='Extract CPEs from CVE files by year')
    parser.add_argument('--year', '-y', help='Year to process', default='2025')
    parser.add_argument('--download-cves', '-dcves', action="store_true", help='Download latest CVEs from NVD (format 2.0) for the specified year', default='')
    parser.add_argument('--download-cpe-matches', '-dcpe', action="store_true", help='Download latest CPE matches from NVD (format 2.0)', default='')

    # Parse arguments
    args = parser.parse_args()
    if int(args.year) < 2024:
        print("Unsupported year")
        exit()

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

    if args.download_cpe_matches is True:
        print("[+] Downloading CPE matches from NVD feeds")
        r = requests.get('https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.zip', stream=True)
        with open(f"{BASEDIR}/tmp-nvd/nvdcpematch-2.0.zip", 'wb') as f:
            pbar = tqdm(unit="B", unit_scale=True, total=int(r.headers['Content-Length']), desc='nvdcpematch-2.0.zip')
            for chunk in r.iter_content(chunk_size=1024):
                f.write(chunk)
                pbar.update(1024)
            pbar.close()
    
    # print("[+] Unzipping and loading CPE matches from NVD")
    cpe_matches = {}
    cpe_matches_archive = zipfile.ZipFile(f"{BASEDIR}/tmp-nvd/nvdcpematch-2.0.zip", 'r')
    # print(cpe_matches_archive.namelist())
    for cm_file in cpe_matches_archive.namelist():
        with cpe_matches_archive.open(cm_file) as f:
            cm_data = json.load(f)
            for match_string in cm_data["matchStrings"]:
                if "matches" in match_string["matchString"].keys():
                    cpe_matches[match_string["matchString"]["matchCriteriaId"]] = match_string["matchString"]["matches"]
    # print(len(cpe_matches.keys()), "CPE matches loaded from NVD")

    
    nvdcve_filename_zip = f"nvdcve-2.0-{args.year}.json.zip"
    if args.download_cves is True:
        print("[+] Downloading CVE dictionary from NVD feeds")
        r = requests.get(f'https://nvd.nist.gov/feeds/json/cve/2.0/{nvdcve_filename_zip}', stream=True)
        with open(f"{BASEDIR}/tmp-nvd/{nvdcve_filename_zip}", 'wb') as f:
            pbar = tqdm(unit="B", unit_scale=True, total=int(r.headers['Content-Length']), desc=nvdcve_filename_zip)
            for chunk in r.iter_content(chunk_size=1024):
                f.write(chunk)
                pbar.update(1024)
            pbar.close()

    print("[+] Unzipping and loading CVE dictionaries from NVD")
    new_cves_archive = zipfile.ZipFile(f"{BASEDIR}/tmp-nvd/{nvdcve_filename_zip}", 'r')
    new_cves_jsonfile = new_cves_archive.open(new_cves_archive.namelist()[0])
    new_cves_list = json.loads(new_cves_jsonfile.read())["vulnerabilities"]
    # Prepare dict for performance sorting
    new_cves = {}
    for item in new_cves_list:
        if "cve" in item and "configurations" in item["cve"]:
            new_cves[item["cve"]["id"]] = item["cve"]["configurations"]
    # print(new_cves["CVE-2025-53760"])

    # Prepare CVE listing
    cves_dir = os.path.join(BASEDIR, "data/")
    cve_files = []

    # Look for CVE candidates
    for year_dir in sorted(os.listdir(cves_dir)):
        if year_dir != str(args.year):
            continue

        year_dir_path = os.path.join(cves_dir, year_dir)
        if os.path.isdir(year_dir_path) is False:
            continue

        for cve_file in sorted(os.listdir(year_dir_path)):
            cve_file_path = os.path.join(year_dir_path, cve_file)
            cve_files.append(cve_file_path)

    nb_matches = 0
    pbar = tqdm(cve_files)
    for cve_file in pbar:
        cve_id = os.path.basename(cve_file).replace(".json", "")
        if cve_id not in new_cves:
            continue
        
        # Loop over CVEs v2-formatted and limit to valid candidates
        matching_cpes = []
        for conf in new_cves[cve_id]:
            for node in conf["nodes"]:
                if "cpeMatch" in node:
                    for cpe_match in node["cpeMatch"]:
                        if cpe_match["vulnerable"] is True:
                            # print(cve_id, cpe_match)

                            # Limit CPE enrichment to Patrowl's monitored technologies only
                            vendor = cpe_match['criteria'].split(":")[3]
                            product = cpe_match['criteria'].split(":")[4]
                            if vendor in patrowl_vendors and product in patrowl_vendors[vendor]:
                                # print(cve_id, cpe_match)
                                # Check the CPE is not dynamic
                                if set(cpe_criterias).isdisjoint(cpe_match.keys()):
                                    # print("  - Found static CPE:", cpe_match["criteria"])
                                    matching_cpes.append(cpe_match["criteria"])
                                else:
                                    # print("  - Found dynamic CPE:", cpe_match["criteria"])
                                    if cpe_match["matchCriteriaId"] in cpe_matches:
                                        mcid = cpe_match["matchCriteriaId"]
                                        # print(mcid, cpe_matches[mcid])
                                        for cpe in cpe_matches[mcid]:
                                            # print(cpe["cpeName"])
                                            matching_cpes.append(cpe["cpeName"])
            matching_cpes = clean_duplicated_cpes(conf["nodes"], matching_cpes)
    

        # Check if updates have been found and update CVE file
        if len(matching_cpes) > 0:
            matching_cpes = sorted(set(matching_cpes))  # Remove duplicates
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

            # Reopen the CVE file
            new_file_content = {}
            with open(cve_file, 'r') as inputfile:
                new_file_content = json.load(inputfile)
                new_file_content["configurations"]["nodes"].append(new_node)
                new_file_content["lastModifiedDate"] = datetime.now().strftime("%Y-%m-%dT%H:%MZ")
                # print(f"New node created for {cve_file}: {new_node}")
                # print(f"Updated file content for {cve_file}: {new_file_content}")

            # Write updates into file
            with open(cve_file, "w") as f:
                json.dump(new_file_content, f)
        
        nb_matches += len(matching_cpes)
        pbar.set_description("Matching CPEs: %i" % nb_matches)


if __name__ == "__main__":
    main()
