#!/bin/bash
display_usage() {
	echo "This script fetch update, create dump and diffs as json files."
	echo -e "\nUsage: $0 \n"
}

DO_DATA_UPDATE=1
DO_PUSH=0

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

start_time="$(date -u +%s)"
current_date=$(python -c 'from datetime import datetime as dt; print(dt.today().strftime("%Y-%m-%d"))')
current_datetime=$(python -c 'from datetime import datetime as dt; print(dt.today().strftime("%Y-%m-%d %H:%M:%S"))')


[ $DO_DATA_UPDATE -eq 1 ] && {
	env/bin/python CWE/fetch-and-update.py
	env/bin/python CPE/fetch-and-update.py
	env/bin/python CVE/fetch-and-update.py
	env/bin/python VIA/fetch-and-update.py
}

echo "${current_datetime}" > lastupdate.txt

[ $DO_PUSH -eq 1 ] && {
	git add .
	git commit -m "data-update-${current_datetime}"
	git push origin :refs/tags/$current_date
	git tag -f $current_date
	git push && git push --tags
}

end_time="$(date -u +%s)"
elapsed="$(($end_time-$start_time))"
echo "Total of $elapsed seconds elapsed"
