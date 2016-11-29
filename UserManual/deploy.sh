#!/bin/bash

# set NIC promiscuous mode
cat /etc/rc.local | grep "promiscuous mode" -q
if [ ! $? -eq 0 ]; then
    cat >> /etc/rc.local <<EOF
# enable interface promiscuous mode!
for eth in {p2p1,p2p2,p2p3,p2p4}; do
    ifconfig \$eth up && ifconfig \$eth promisc
done
EOF
fi
chmod +x /etc/rc.local
