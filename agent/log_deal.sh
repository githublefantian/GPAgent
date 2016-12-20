#!/usr/bin/env bash

source /root/agent/agent.env


for file in `ls ${LOG_DIR}/*.log`; do
    filename=`basename ${file}`
    [ "${filename:0:2}" == "20" ] && continue
    year=`date +%Y`
    month=`date +%m`
    let month--
    [ ${month} -eq 0 ] && month=12 && let year--
    [ ${#month} -eq 1 ] && month="0${month}"
    prefix="${year}${month}_"
    archive_fn=${prefix}${filename}
    cp ${file} ${file%/*}/${archive_fn}
    [ $? -eq 0 ] && echo "===== archive ${archive_fn} success! =====" > ${file}
done
