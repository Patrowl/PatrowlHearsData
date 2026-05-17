# PatrowlHearsData

[![Stars](https://img.shields.io/github/stars/Patrowl/PatrowlHearsData?style=flat-square)](https://github.com/Patrowl/PatrowlHearsData/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/Patrowl/PatrowlHearsData?style=flat-square)](https://github.com/Patrowl/PatrowlHearsData/commits/main)
[![License](https://img.shields.io/github/license/Patrowl/PatrowlHearsData?style=flat-square)](./LICENSE)

Open-source vulnerability intelligence data and collection scripts for CVE, CPE, CWE, EPSS, KEV, exploit, and threat feeds.

## Table of Contents
- [Overview](#overview)
- [What is included](#what-is-included)
- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
- [How updates work](#how-updates-work)
- [Use cases](#use-cases)
- [Security](#security)
- [Contributing](#contributing)
- [Support](#support)
- [License](#license)

## Overview
[PatrowlHears](https://www.patrowlhears.io/) is a real-time vulnerability intelligence platform focused on CVE, exploit, and threat monitoring.

This repository contains the public raw datasets and scraping scripts that feed the platform. It is useful if you want to:
- mirror public vulnerability intelligence sources,
- inspect how feeds are collected and updated,
- build your own enrichment pipeline on top of structured security data.

## What is included
- **CVE** data and supporting metadata
- **CPE** and **CWE** reference data
- **EPSS** and **KEV** datasets
- **VIA** and exploit-related collection sources
- update scripts such as `fetch-updates.sh`

## Repository layout
```text
CPE/             Product enumeration data
CVE/             Vulnerability records and related data
CWE/             Weakness taxonomy data
EPSS/            Exploit Prediction Scoring System data
KEV/             Known Exploited Vulnerabilities data
VIA/             Additional intelligence sources
fetch-updates.sh Update workflow entrypoint
install.sh       Local setup helper
requirements.txt Python dependencies
```

## Quick start
### Prerequisites
- Python 3
- pip / virtualenv
- Git

### Installation
Use the provided installer:

```bash
chmod +x install.sh
./install.sh
```

Or install manually:

```bash
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

### Usage
Fetch or refresh the public datasets:

```bash
./fetch-updates.sh
```

After the update completes, inspect the dataset folders directly or wire them into your own analysis pipeline.

## How updates work
The repository is organized around source-specific datasets plus scripts that refresh those datasets from public intelligence feeds. This makes it easy to automate scheduled sync jobs or selectively consume only the data families you need.

## Use cases
- vulnerability intelligence enrichment
- internal security dashboards
- exploit and threat feed aggregation
- research workflows around CVE/CPE/CWE relationships

## Security
If you need to report a vulnerability in the project itself, please follow [SECURITY.md](./SECURITY.md).

## Contributing
Contributions are welcome. A good starting point is to:
1. open an issue describing the improvement or data-source problem,
2. test your changes on a local clone,
3. submit a pull request with context about the affected feed or script.

Project-wide community expectations are documented in the [Patrowl code of conduct](https://github.com/Patrowl/PatrowlDocs/blob/master/support/code_of_conduct.md).

## Support
- Issues: https://github.com/Patrowl/PatrowlHearsData/issues
- Gitter: https://gitter.im/PatrowlHears/Support
- Email: getsupport@patrowl.io
- Product site: https://patrowlhears.io

## License
Released under the [Apache 2.0 License](./LICENSE).
