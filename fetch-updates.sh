#!/bin/bash
display_usage() {
	echo "This script fetch update, create dump and diffs as json files."
	echo -e "\nUsage: $0 \n"
}

DO_DATA_UPDATE=1
DO_PUSH=1

while (( "$#" )); do
  case "$1" in
    -n|--no-data-update)
      DO_DATA_UPDATE=0
      shift
      ;;
    -l|--no-data-push)
      DO_PUSH=0
      shift
      ;;
    # -b|--my-flag-with-argument)
    #   if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
    #     MY_FLAG_ARG=$2
    #     shift 2
    #   else
    #     echo "Error: Argument for $1 is missing" >&2
    #     exit 1
    #   fi
    #   ;;
    -*|--*=) # unsupported flags
      echo "Error: Unsupported flag $1" >&2
      exit 1
      ;;
    *) # preserve positional arguments
      display_usage
      exit 1
      ;;
  esac
done

start_time="$(date -u +%s)"
current_date=$(python -c 'from datetime import datetime as dt; print(dt.today().strftime("%Y-%m-%d"))')
current_datetime=$(python -c 'from datetime import datetime as dt; print(dt.today().strftime("%Y-%m-%d %H:%M:%S"))')


[ $DO_DATA_UPDATE -eq 1 ] && {
	python CWE/fetch-and-update.py
	python CPE/fetch-and-update.py
	python CVE/fetch-and-update.py
	python VIA/fetch-and-update.py
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
