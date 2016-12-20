#!/bin/bash

chmod +x /etc/rc.local
chmod +x /root/agent/*.sh

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

# set python agent.py startup
cat /etc/rc.local | grep "python agent.py startup" -q
if [ ! $? -eq 0 ]; then
    cat >> /etc/rc.local <<EOF

# enable python agent.py startup!
python /root/agent/agent.py &
EOF
fi



# set crontab python agent.py
cat /etc/crontab | grep "crontab python agent.py" -q
if [ ! $? -eq 0 ]; then
    cat >> /etc/crontab <<EOF

# enable crontab python agent.py!
*/1 * * * * root ((ps aux | grep python | grep agent.py | grep -qv grep) || (python /root/agent/agent.py &)) &> /dev/null
EOF
fi
