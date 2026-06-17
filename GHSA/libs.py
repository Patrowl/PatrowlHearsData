from cvss import CVSS3, CVSS4

# Check if the given path exists in the dictionary
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

def parse_cvss(cvss_score):
    cvss_score = cvss_score.rstrip("/")
    version = cvss_score.split("/")[0].replace("CVSS:", "")
    cvss = None
    if version in ["3.0", "3.1"]:
        try:
            
            cvss = CVSS3(cvss_score)
        except Exception as e:
            print(f"Error parsing CVSS score '{cvss_score}': {e}")
            pass
    elif version == "4.0":
        try:
            cvss = CVSS4(cvss_score)
        except Exception as e:
            print(f"Error parsing CVSS score '{cvss_score}': {e}")
            pass
    
    return cvss.as_json(minimal=True) if cvss else {
        "version": version,
        "vectorString": cvss_score
    }


def format_impacts(severities):
    impacts = {}

    for severity in severities:
        cvss_data = parse_cvss(severity["score"])
        # print(f"[+] Parsed CVSS data: {cvss_data}")
        if cvss_data["version"] in ["3.0", "3.1"]:
            cvss_metrics = {
                "baseMetricV3": {
                    "cvssV3": cvss_data,
                    "exploitabilityScore": 0.0,
                    "impactScore": 0.0
                }
            }
            cvss_metrics["baseMetricV3"]["cvssV3"]["version"] = cvss_data["version"]
            impacts.update(cvss_metrics)
        elif cvss_data["version"] == "4.0":
            cvss_metrics = {
                "baseMetricV4": {
                    "cvssV4": cvss_data,
                    "exploitabilityScore": 0.0,
                    "impactScore": 0.0
                }
            }
            cvss_metrics["baseMetricV4"]["cvssV4"]["version"] = cvss_data["version"]
            impacts.update(cvss_metrics)
        
    return impacts