#!/bin/bash

display_usage() {
	echo "This script fetches updates, creates dumps, and diffs as JSON files."
	echo -e "\nUsage: $0 \n"
}

DO_DATA_UPDATE=1
DO_PUSH=0
GIT_USERNAME=${GIT_USERNAME:-}
GIT_PASSWORD=${GIT_PASSWORD:-}
GIT_ORIGIN="origin"

while (( "$#" )); do
  case "$1" in
    -n|--no-data-update)
      DO_DATA_UPDATE=0
      ;;
    -p|--push-data)
      DO_PUSH=1
      ;;
    -u|--username)
      GIT_USERNAME=$2
      ;;
    -w|--password)
      GIT_PASSWORD=$2
      ;;
    -*|--*=) # unsupported flags
      echo "Error: Unsupported flag $1" >&2
			display_usage
      exit 1
      ;;
    *)
      display_usage
      exit 1
      ;;
  esac
  shift
done

if [[ -n ${GIT_USERNAME} && -n ${GIT_PASSWORD} ]]; then
	GIT_ORIGIN="https://${GIT_USERNAME}:${GIT_PASSWORD}@github.com/Patrowl/PatrowlHearsData"
fi

start_time="$(date -u +%s)"
echo "[+] Started at $start_time"

current_date=$(python3 -c 'from datetime import datetime as dt; print(dt.today().strftime("%Y-%m-%d"))')
current_datetime=$(python3 -c 'from datetime import datetime as dt; print(dt.today().strftime("%Y-%m-%d %H:%M:%S"))')

echo "[+] Pull latest updates from Github"
git pull

if [ $DO_DATA_UPDATE -eq 1 ]; then
	for dir in CWE CPE CVE VIA EPSS; do
		env/bin/python $dir/fetch-and-update.py
	done
fi

echo "${current_datetime}" > lastupdate.txt

if [ $DO_PUSH -eq 1 ]; then
	git add .
	git commit -m "data-update-${current_datetime}"
	git push ${GIT_ORIGIN} :refs/tags/$current_date
	git tag -f $current_date
	git push && git push --tags
fi

end_time="$(date -u +%s)"
elapsed="$(($end_time-$start_time))"
echo "Total of $elapsed seconds elapsed for process"
