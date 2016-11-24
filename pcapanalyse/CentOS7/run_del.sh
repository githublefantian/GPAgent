#!/usr/bin/bash
export IF_DEL_PCAPNG=1
LOGFILE=run.log

rm -rf ./dist/*.csv . &> /dev/null
sh http_filter.sh &> $LOGFILE
(time ./dist/http-filter-v2.2.2) &>> $LOGFILE
mv ./dist/*.csv . &> /dev/null
