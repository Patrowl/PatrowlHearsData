#!/bin/bash
display_usage() {
	echo "This script fetch update, create dump and diffs as json files."
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
      shift
      ;;
    -p|--push-data)
      DO_PUSH=1
      shift
      ;;
    -u|--username)
      echo "Username: $2"
			GIT_USERNAME=$2
			shift
			shift
      ;;
    -w|--password)
      echo "password: $2"
			GIT_PASSWORD=$2
			shift
			shift
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
done

[[ ${GIT_USERNAME} -ne "" && ${GIT_PASSWORD} -ne "" ]] && {
	GIT_ORIGIN="https://${GIT_USERNAME}:${GIT_USERNAME}@github.com/Patrowl/PatrowlHearsData"
}

start_time="$(date -u +%s)"
echo "[+] Started at $start_time"

current_date=$(python3 -c 'from datetime import datetime as dt; print(dt.today().strftime("%Y-%m-%d"))')
current_datetime=$(python3 -c 'from datetime import datetime as dt; print(dt.today().strftime("%Y-%m-%d %H:%M:%S"))')

echo "[+] Pull latest updates from Github"
git pull

[ $DO_DATA_UPDATE -eq 1 ] && {
	env/bin/python CWE/fetch-and-update.py
	env/bin/python CPE/fetch-and-update.py
	env/bin/python CVE/fetch-and-update.py
	env/bin/python VIA/fetch-and-update.py
	env/bin/python EPSS/fetch-and-update.py
	env/bin/python KEV/fetch-and-update.py
}

echo "${current_datetime}" > lastupdate.txt

[ $DO_PUSH -eq 1 ] && {
	git add .
	git commit -m "data-update-${current_datetime}"
	# git push origin :refs/tags/$current_date
	git push ${GIT_ORIGIN} :refs/tags/$current_date
	git tag -f $current_date
	git push && git push --tags
}

end_time="$(date -u +%s)"
elapsed="$(($end_time-$start_time))"
echo "Total of $elapsed seconds elapsed"
