#!/usr/bin/env -S python3 -OO
# coding:utf8

# Copyright (c) 2020-2025, Patrowl and contributors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.  Redistributions in binary
# form must reproduce the above copyright notice, this list of conditions and the
# following disclaimer in the documentation and/or other materials provided with
# the distribution
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
import os
import os
import re
import sys
import time
import argparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json
from datetime import datetime, timedelta, timezone
from dateutil.parser import parse
from tqdm import tqdm
from libs import probe, get_cpe_matches, get_monitored_technologies
BASEDIR = os.path.dirname(os.path.realpath(__file__))
DAYS_BEFORE = int(os.environ.get("DAYS_BEFORE", 2))
NUCLEI_VENDORS_FILE = os.path.join(BASEDIR, "nuclei_vendors.txt")

# NVD CVE API v2 (https://nvd.nist.gov/developers/vulnerabilities)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
RESULTS_PER_PAGE = 2000             # API maximum
MAX_RANGE_DAYS = 120                # API maximum for any date range
# Rate limits: 5 requests / 30s without API key, 50 requests / 30s with an API key
REQUEST_DELAY = 0.6 if NVD_API_KEY else 6

# Filled in main(), used by format_cpes()
cpe_matches = {}
patrowl_vendors = {}

# Format references to the required structure
def format_references(references):
    res_references = []

    for reference in references:
        url = probe(reference, ["url"])
        if url == "":
            continue

        res_references.append({
            "url": url,
            "name": "",
            "refsource": "",
            "tags": probe(reference, ["tags"], [])
        })

    return res_references

# Format problem types (CWE) to the required structure
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
    cwe_values = []

    for problem_type in problem_types:
        if "description" not in problem_type.keys():
            continue

        for description in problem_type["description"]:
            value = "NVD-CWE-noinfo"
            if "CWE-" in description["value"]:
                value = description["value"].split(' ')[0]
            
            if value in cwe_values:
                continue
            cwe_values.append(value)

            res_problemtypes.append({
                "lang": "en",
                "value": value
            })

    if len(res_problemtypes) == 0:
        return def_problemtypes

    # return res_problemtypes
    return [{"description": res_problemtypes}]

def _select_nvd_cvss(cvss_metrics):
    # select source ""nvd@nist.gov"" as default. If not present, select the first one.
    for metric in cvss_metrics:
        if metric.get("source") == "nvd@nist.gov":
            metric.pop("source")
            metric.pop("type")
            return metric
    metric = cvss_metrics[0]
    metric.pop("source")
    metric.pop("type")
    return metric

def format_impacts(metrics):
    impacts = {}

    if "cvssMetricV2" in metrics.keys():
        cvss_metric = _select_nvd_cvss(metrics["cvssMetricV2"])
        cvss_metric["cvssV2"] = cvss_metric.pop("cvssData")
        impacts.update({
            "baseMetricV2": {
                "cvssV2": cvss_metric["cvssV2"],
                "exploitabilityScore": cvss_metric["exploitabilityScore"],
                "impactScore": cvss_metric["impactScore"],
                "severity": cvss_metric["baseSeverity"],
                "obtainAllPrivilege": cvss_metric.get("obtainAllPrivilege", False),
                "obtainUserPrivilege": cvss_metric.get("obtainUserPrivilege", False),
                "obtainOtherPrivilege": cvss_metric.get("obtainOtherPrivilege", False),
                "userInteractionRequired": cvss_metric.get("userInteractionRequired", False)
            }
        })
    if "cvssMetricV30" in metrics.keys():
        cvss_metric = _select_nvd_cvss(metrics["cvssMetricV30"])
        cvss_metric["cvssV3"] = cvss_metric.pop("cvssData")
        impacts.update({
            "baseMetricV3": cvss_metric
        })
    if "cvssMetricV31" in metrics.keys():
        # cvss_metric = metrics["cvssMetricV31"][0]
        cvss_metric = _select_nvd_cvss(metrics["cvssMetricV31"])
        cvss_metric["cvssV3"] = cvss_metric.pop("cvssData")
        impacts.update({
            "baseMetricV3": cvss_metric
        })
    if "cvssMetricV40" in metrics.keys():
        cvss_metric = _select_nvd_cvss(metrics["cvssMetricV40"])
        cvss_metric["cvssV4"] = cvss_metric.pop("cvssData")
        impacts.update({
            "baseMetricV4": cvss_metric
        })

    return impacts

def format_cpes(configurations):
    global cpe_matches, patrowl_vendors
    cpes = {
        "CVE_data_version": "4.0",
        "nodes": []
    }

    for configuration in configurations:
        for node in configuration.get("nodes", []):
            new_node = {
                "operator": node.get("operator", "OR"),
                "negate": node.get("negate", False),
                "children": [],
                "cpe_match": [],
            }
            for cpe_match in node.get("cpeMatch", []):
                new_cpe_match = {
                    "vulnerable": cpe_match.get("vulnerable", False),
                    "cpe23Uri": cpe_match.get("criteria", ""),
                    "matchCriteriaId" : cpe_match.get("matchCriteriaId", ""),
                    "cpe_name": []
                }
                for field in ["versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"]:
                    if field in cpe_match.keys():
                        new_cpe_match[field] = cpe_match[field]
                new_node["cpe_match"].append(new_cpe_match)

                # Limit CPE enrichment to Patrowl's monitored technologies only
                if len(new_cpe_match.keys()) > 4:
                    # Dynamic CPE, keep the match CriteriaId for later processing
                    vendor = cpe_match['criteria'].split(":")[3]
                    product = cpe_match['criteria'].split(":")[4]
                    # print("  - Found dynamic CPE:", cpe_match["criteria"], vendor, product, cpe_match.get("matchCriteriaId", ""))
                    if vendor in patrowl_vendors and product in patrowl_vendors[vendor]:
                        # Check the CPE is dynamic or not
                        # print("  - Found monitored & dynamic CPE:", cpe_match["criteria"])
                        mcid = cpe_match["matchCriteriaId"]
                        matching_cpes = []

                        if mcid in cpe_matches:
                            for cpe in cpe_matches[mcid]:
                                matching_cpes.append(cpe["cpeName"])
                        
                        # matching_cpes = clean_duplicated_cpes([node], matching_cpes)
                        # print("    - Enriched dynamic CPEs:", matching_cpes)
                        if len(matching_cpes) > 0:
                            matching_cpes = sorted(set(matching_cpes))  # Remove duplicates
                            for cpe in matching_cpes:
                                new_node["cpe_match"].append({
                                    "vulnerable": True,
                                    "cpe23Uri": cpe,
                                    "cpe_name": []
                            })
    
            cpes["nodes"].append(new_node)

    return cpes

def make_session():
    session = requests.Session()
    retries = Retry(
        total=6,
        backoff_factor=2,            # waits 2s, 4s, 8s, 16s... between retries
        status_forcelist=[403, 429, 500, 502, 503, 504],  # NVD answers 403 when rate limited
        allowed_methods=["GET"],
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    if NVD_API_KEY:
        session.headers.update({"apiKey": NVD_API_KEY})
    return session

# Format a NVD API CVE entry to the required structure (same as fetch-and-update.py)
def format_cve(cve):
    date_updated = parse(cve["lastModified"], ignoretz=True)
    cve_id = probe(cve, ["id"])

    return {
        "publishedDate": parse(cve["published"], ignoretz=True).strftime("%Y-%m-%dT%H:%MZ"),
        "lastModifiedDate": date_updated.strftime("%Y-%m-%dT%H:%MZ"),
        "cve": {
            "data_type": "CVE",
            "data_format": "MITRE",
            "data_version": "1.0",
            "CVE_data_meta": {
                "ID": cve_id,
                "ASSIGNER": probe(cve, ["sourceIdentifier"])
            },
            "description": {
                "description_data": probe(cve, ["descriptions"], []),
            },
            "references": {
                "reference_data": format_references(probe(cve, ["references"], [])),
            },
            "problemtype": {
                "problemtype_data": format_problem_types(probe(cve, ["weaknesses"], [])),
            }
        },
        "impact": format_impacts(probe(cve, ["metrics"], {})),
        "configurations": format_cpes(probe(cve, ["configurations"], {}))
    }

def write_cve(cve_content, output_dir):
    cve_id = cve_content["cve"]["CVE_data_meta"]["ID"]
    year_dir = os.path.join(output_dir, cve_id.split('-')[1])
    if not os.path.exists(year_dir):
        os.makedirs(year_dir)

    with open(f"{year_dir}/{cve_id}.json", 'w') as outfile:
        json.dump(cve_content, outfile)

# Split [start, end] into consecutive ranges accepted by the API
def date_ranges(start, end):
    while start < end:
        range_end = min(start + timedelta(days=MAX_RANGE_DAYS), end)
        yield start, range_end
        start = range_end

def format_api_date(date):
    return date.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

# Yield raw CVE entries from the NVD API, following pagination
def fetch_cves(session, params, desc):
    start_index = 0
    pbar = None
    while True:
        r = session.get(NVD_API_URL, params={**params, "resultsPerPage": RESULTS_PER_PAGE, "startIndex": start_index}, timeout=(10, 120))
        r.raise_for_status()
        data = r.json()

        if pbar is None:
            pbar = tqdm(total=data["totalResults"], desc=desc)
        for vulnerability in data["vulnerabilities"]:
            pbar.update(1)
            yield vulnerability["cve"]

        start_index += data["resultsPerPage"]
        if data["resultsPerPage"] == 0 or start_index >= data["totalResults"]:
            break
        time.sleep(REQUEST_DELAY)
    pbar.close()
    time.sleep(REQUEST_DELAY)

def parse_utc_date(value):
    date = parse(value)
    if date.tzinfo is None:
        return date.replace(tzinfo=timezone.utc)
    return date.astimezone(timezone.utc)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Collect new and updated CVEs from the NVD CVE API v2 and write them in data/<year>/<CVE-ID>.json. "
                    "By default, CVEs modified during the last DAYS_BEFORE days (env, default 2) are collected. "
                    "Set NVD_API_KEY env var to raise the API rate limits.")
    parser.add_argument("--cve", help="Collect a single CVE entry (ex: CVE-2024-3400)")
    parser.add_argument("--year", type=int, help="Only keep CVE IDs of this year (ex: 2024). "
                        "Without --from-date, collects all CVEs of this year published since its beginning")
    parser.add_argument("--from-date", type=parse_utc_date,
                        help="Collect CVEs newly published since this date (API 'pubStartDate', UTC, ex: 2026-10-01 or 2026-10-01T12:00:00)")
    parser.add_argument("--output-dir", default=os.path.join(BASEDIR, "data"),
                        help="Output directory (default: %(default)s)")
    args = parser.parse_args()

    if args.cve:
        args.cve = args.cve.strip().upper()
        if not re.match(r"^CVE-\d{4}-\d{4,}$", args.cve):
            parser.error(f"invalid CVE ID '{args.cve}'")
        if args.year or args.from_date:
            parser.error("--cve can't be combined with --year or --from-date")
    if args.from_date and args.from_date > datetime.now(timezone.utc):
        parser.error("--from-date is in the future")
    return args

def main():
    global cpe_matches, patrowl_vendors
    args = parse_args()
    session = make_session()

    # Loading latest CPE matches from NVD feeds
    cpe_matches = get_cpe_matches(BASEDIR)

    # Load monitored technologies from Patrowl's Nuclei templates
    patrowl_vendors = get_monitored_technologies(NUCLEI_VENDORS_FILE)

    now = datetime.now(timezone.utc)
    if args.cve:
        queries = [({"cveId": args.cve}, args.cve)]
    elif args.from_date or args.year:
        # A CVE ID of a given year is published during that year or later (rarely a few weeks before)
        start = args.from_date or datetime(args.year - 1, 10, 1, tzinfo=timezone.utc)
        queries = [
            ({"pubStartDate": format_api_date(s), "pubEndDate": format_api_date(e)}, f"published {s:%Y-%m-%d} -> {e:%Y-%m-%d}")
            for s, e in date_ranges(start, now)
        ]
    else:
        start = now - timedelta(days=DAYS_BEFORE)
        queries = [
            ({"lastModStartDate": format_api_date(s), "lastModEndDate": format_api_date(e)}, f"modified {s:%Y-%m-%d %H:%M} -> {e:%Y-%m-%d %H:%M}")
            for s, e in date_ranges(start, now)
        ]

    print("[+] Downloading CVEs from NVD API v2" + ("" if NVD_API_KEY else " (no NVD_API_KEY set, rate limited)"))
    nb_written = 0
    for params, desc in queries:
        for cve in fetch_cves(session, params, desc):
            cve_id = probe(cve, ["id"])
            if args.year and cve_id.split('-')[1] != str(args.year):
                continue
            write_cve(format_cve(cve), args.output_dir)
            nb_written += 1

    print(f"[+] {nb_written} CVE files created or updated in {args.output_dir}")
    if args.cve and nb_written == 0:
        print(f"[-] {args.cve} not found in NVD")
        sys.exit(1)

if __name__ == "__main__":
    main()
