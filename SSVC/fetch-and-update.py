import os
import shutil
import git
import datetime
from dateutil.parser import parse
import json
from tqdm import tqdm
BASEDIR = os.path.dirname(os.path.realpath(__file__))
BASEDIR_DATA = f"{BASEDIR}/data"
BASEDIR_TMP = f"{BASEDIR}/tmp"

print("[+] Downloading SSVC reports from Github repo cisagov/vulnrichment")
if os.path.exists(BASEDIR_TMP) and os.path.isdir(BASEDIR_TMP):
    shutil.rmtree(BASEDIR_TMP)
git.Repo.clone_from(
    'https://github.com/cisagov/vulnrichment',
    BASEDIR_TMP,
    multi_options=[
        '--depth=1',
        '--single-branch',
    ],
)
shutil.rmtree(f"{BASEDIR_TMP}/.git")

for year in tqdm(range(1999, datetime.datetime.now().year + 1)):
    # Check if dir exists
    if not os.path.exists(f"{BASEDIR_TMP}/{year}"):
        continue

    if not os.path.exists(f"{BASEDIR_DATA}/{year}"):
        os.makedirs(f"{BASEDIR_DATA}/{year}")

    for interm_dir in tqdm(os.listdir(f"{BASEDIR_TMP}/{year}"), desc=f"[+] Processing {year}", leave=False):
        for filename in os.listdir(f"{BASEDIR_TMP}/{year}/{interm_dir}"):
            if filename.endswith(".json"):
                with open(f"{BASEDIR_TMP}/{year}/{interm_dir}/{filename}", "r") as f:
                    data = json.load(f)
                    # print(f"[+] Processing {year}/{interm_dir}/{filename}")
                    if "containers" in data and "adp" in data["containers"]:
                        for adp_node in data["containers"]["adp"]:
                            if "title" in adp_node and adp_node["title"] == "CISA ADP Vulnrichment":
                                ssvc_content = {}
                                references_content = []

                                if "metrics" in adp_node:
                                    for metric in adp_node["metrics"]:
                                        if "other" in metric and metric["other"]["type"] == "ssvc":
                                            ssvc_content = metric["other"]["content"]

                                if "references" in adp_node:
                                    for reference in adp_node["references"]:
                                        if "tags" in reference and "exploit" in reference["tags"]:
                                            references_content.append({
                                                "url": reference["url"],
                                                "tags": reference["tags"]
                                            })
                                            # print(f"[+] Found exploit reference: {reference['url']}")
                                if len(ssvc_content) > 0 or len(references_content) > 0:
                                    with open(f"{BASEDIR_DATA}/{year}/{filename}", "w") as f_out:
                                        f_content = {
                                            "ssvc": ssvc_content,
                                            "references": references_content
                                        }
                                        json.dump(f_content, f_out, indent=4)
