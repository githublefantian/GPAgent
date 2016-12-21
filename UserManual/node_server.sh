#!/bin/bash

SLEEP_SECONDS=2    # 程序检测时间间隔(秒)
NODE_SERVER_JS="/root/guopai/server.js"
NODE_SERVER_LOG="/root/guopai/log/server.log"


[ ! -d ${NODE_SERVER_LOG%/*} ] && mkdir ${NODE_SERVER_LOG%/*}

chmod +x /etc/rc.local
chmod +x /root/guopai/*.sh


# set node server.js startup
cat /etc/rc.local | grep "node server.js" -q
if [ ! $? -eq 0 ]; then
    cat >> /etc/rc.local <<EOF

# enable node server.js startup!
sh /root/guopai/node_server.sh &
EOF
fi

# set node server.js crontab
cat /etc/crontab | grep "node server.js" -q
if [ ! $? -eq 0 ]; then
    cat >> /etc/crontab <<EOF

# enable node server.js crontab!
*/1 * * * * root (ps aux | grep "node_server.sh" | grep -qv grep) || (sh /root/guopai/node_server.sh &) &> /dev/null
EOF
fi


##################### main  loop #####################
while :; do
    sleep ${SLEEP_SECONDS}
    ps aux | grep "node server.js" | grep -qv grep
    if [ ! $? -eq 0 ]; then
        echo "=============[$0] node server.js restart! (`date`)=============" >> ${NODE_SERVER_LOG}
        cd ${NODE_SERVER_JS%/*}
        node ${NODE_SERVER_JS##*/} &>> ${NODE_SERVER_LOG}
    fi
done

