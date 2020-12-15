#!/bin/bash
display_usage() {
	echo "This script fetch update, create dump and diffs as json files."
	echo -e "\nUsage: $0 \n"
}


python CWE/fetch-and-update.py
# python CPE/fetch-and-update.py
# python CVE/fetch-and-update.py
python VIA/fetch-and-update.py
