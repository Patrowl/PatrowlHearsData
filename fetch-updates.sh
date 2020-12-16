#!/bin/bash
display_usage() {
	echo "This script fetch update, create dump and diffs as json files."
	echo -e "\nUsage: $0 \n"
}

start_time="$(date -u +%s)"
current_date=$(python -c 'from datetime import datetime as dt; print(dt.today().strftime("%Y-%m-%d"))')
current_datetime=$(python -c 'from datetime import datetime as dt; print(dt.today().strftime("%Y-%m-%d %H:%M:%S"))')

# python CWE/fetch-and-update.py
# python CPE/fetch-and-update.py
# python CVE/fetch-and-update.py
# python VIA/fetch-and-update.py

echo "${current_datetime}" > lastupdate.txt

git add .
git commit -m "data-update-${current_datetime}"
git push

end_time="$(date -u +%s)"
elapsed="$(($end_time-$start_time))"
echo "Total of $elapsed seconds elapsed"
