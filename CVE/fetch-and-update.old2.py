#!/bin/python3
import re
import os
import shutil
import git
import json
from datetime import datetime, timedelta, timezone
from dateutil.parser import parse
from tqdm import tqdm
BASEDIR = os.path.dirname(os.path.realpath(__file__))
DAYS_BEFORE = int(os.environ.get("DAYS_BEFORE", 2))

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

def format_problem_types(problem_types):
    def_problemtypes = [{
        "description": [
            {
                "lang": "en",
                "value": "NVD-CWE-noinfo"
            }
        ]
    }]

    res_problemtypes = []

    for problem_type in problem_types:
        if "descriptions" not in problem_type.keys():
            continue

        for description in problem_type["descriptions"]:
            value = "NVD-CWE-noinfo"
            if "cweId" in description.keys():
                value = description["cweId"]
            elif "description" in description.keys() and "CWE-" in description["description"]:
                value = description["description"].split(' ')[0]
            
            res_problemtypes.append({
                "description": [
                    {
                        "lang": "en",
                        "value": value
                    }
                ]
            })

    if len(res_problemtypes) == 0:
        return def_problemtypes

    return res_problemtypes


def format_impacts(metrics):
    impacts = {}

    for metric in metrics:
        if "cvssV2_0" in metric.keys():
            impacts.update({
                "baseMetricV2": {
                    "cvssV2": metric
                }
            })
        if "cvssV3_0" in metric.keys() or "cvssV3_1" in metric.keys():
            impacts.update({
                "baseMetricV3": {
                    "cvssV3": metric
                }
            })
        if "cvssV4_0" in metric.keys():
            impacts.update({
                "baseMetricV4": {
                    "cvssV4": metric
                }
            })
        if "others" in metric.keys():
            impacts.update(metric)

    return impacts

def format_cpes(data):
    res = {}
    cpes_list = []
    cpe_matches = []

    for affected_product in data:
        
        if set(['vendor', 'product', 'versions']).issubset(affected_product.keys()):
            try:
                # print(affected_product)
                vendor = str(affected_product["vendor"]).lower()
                product = str(affected_product["product"]).lower()
                versions = []
                for version in affected_product["versions"]:
                    if "lessThan" in version.keys():
                        versions.append(version["lessThan"])
                    if "lessThanOrEqual" in version.keys():
                        versions.append(version["lessThanOrEqual"])
                
                for version in versions:
                    cpes_list.append(f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",)
                
                if "cpes" in affected_product.keys():
                    cpes_list.extend(affected_product["cpes"])
                cpes_list = list(set(cpes_list))

            except Exception as e:
                print("Unable to format CPE. Missing keys on", affected_product)
                continue

    for cpe in cpes_list:
        cpe_matches.append(
            {
                "vulnerable": True,
                "cpe23Uri": cpe,
                "cpe_name": []
            }
        )

    res = {
        "CVE_data_version": "4.0",
        "nodes": [
            {
                "operator": "OR",
                "children": [],
                "cpe_match": cpe_matches
            }
        ]
    }

    return res


if not os.path.exists(BASEDIR+'/nvd/'):
    os.makedirs(BASEDIR+'/nvd/')

print("[+] Downloading CVE list from Github repo CVEProject/cvelistV5")
if os.path.exists(BASEDIR+'/tmp') and os.path.isdir(BASEDIR+'/tmp'):
    shutil.rmtree(BASEDIR+'/tmp')
git.Repo.clone_from(
    'https://github.com/CVEProject/cvelistV5',
    BASEDIR+'/tmp',
    depth=1
)

# Check if folders exists
cve_files = []
cves_dir = BASEDIR+"/tmp/cves/"
last_check_date = datetime.now() - timedelta(days=DAYS_BEFORE)

# Look for CVE candidates
for year_dir in sorted(os.listdir(cves_dir)):
    if year_dir not in ["2025", "2024"]:
        continue

    year_dir_path = os.path.join(cves_dir, year_dir)
    if os.path.isdir(year_dir_path) is False:
        continue

    for num_dir in sorted(os.listdir(year_dir_path)):
        num_dir_path = os.path.join(year_dir_path, num_dir)

        for cve_file in sorted(os.listdir(num_dir_path)):
            cve_file_path = os.path.join(num_dir_path, cve_file)
            cve_files.append(cve_file_path)

for cve_file in tqdm(cve_files):
    with open(cve_file, 'r') as inputfile:
        cve_dict = json.load(inputfile)

    date_updated = parse(cve_dict["cveMetadata"]["dateUpdated"], ignoretz=True)
    if last_check_date > date_updated:
        continue

    # Look for problem types
    problem_types = probe(cve_dict, ["containers", "cna", "problemTypes"], [])
    if len(problem_types) == 0:
        problem_types = probe(cve_dict, ["containers", "adp", "problemTypes"], [])
    problemtype_data = format_problem_types(problem_types)

    # Look for CVSS metrics
    cvss_metrics = probe(cve_dict, ["containers", "cna", "metrics"], [])
    cvss_metrics_data = format_impacts(cvss_metrics)

    # Look for CPEs
    cpes = probe(cve_dict, ["containers", "cna", "affected"], [])
    cpes_data = format_cpes(cpes)

    cve_id = probe(cve_dict, ["cveMetadata", "cveId"])

    try:
        cve_published_date_raw = probe(cve_dict, ["cveMetadata", "datePublished"])
        if cve_published_date_raw != "":
            cve_published_date = parse(cve_published_date_raw).strftime("%Y-%m-%dT%H:%MZ")
        
        cve_last_modified_date_raw = probe(cve_dict, ["cveMetadata", "dateUpdated"])
        if cve_last_modified_date_raw != "":
            cve_last_modified_date = parse(cve_last_modified_date_raw).strftime("%Y-%m-%dT%H:%MZ")

        cve_content = {
            "publishedDate": cve_published_date,
            "lastModifiedDate": cve_last_modified_date,
            "cve": {
                "data_type": "CVE",
                "data_format": "MITRE",
                "data_version": probe(cve_dict, ["dataVersion"]),
                "CVE_data_meta": {
                    "ID": cve_id,
                    "ASSIGNER": probe(cve_dict, ["cveMetadata", "assignerShortName"]),
                },
                "description": {
                    "description_data": probe(cve_dict, ["containers", "cna", "descriptions"], []),
                },
                "references": {
                    "reference_data": probe(cve_dict, ["containers", "cna", "references"], []),
                },
                "problemtype": {
                    "problemtype_data": problemtype_data,
                }
            },
            "impact": cvss_metrics_data,
            "configurations": cpes_data
        }
    except Exception as e:
        print(probe(cve_dict, ["cveMetadata", "cveId"]))
        print(e)
        continue

    cve_year = cve_id.split('-')[1]
    if not os.path.exists(BASEDIR+'/data/'+cve_year):
        os.makedirs(BASEDIR+'/data/'+cve_year)

    with open(BASEDIR+'/data/'+cve_year+'/'+cve_id+'.json', 'w') as outfile:
        json.dump(cve_content, outfile)
