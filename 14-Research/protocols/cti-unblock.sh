#!/bin/bash
# CTI: reset blokir attacker .110 agar tiap iterasi MTTD/MTTR independen.
# Dipasang di VICTIM sebagai /usr/local/sbin/cti-unblock.sh (root, 0755),
# dipanggil orchestrator via: ssh korban@victim "sudo -n /usr/local/sbin/cti-unblock.sh"
# (sudoers NOPASSWD: /etc/sudoers.d/cti-unblock)
while iptables -D INPUT -s 192.168.56.110 -j DROP 2>/dev/null; do :; done
exit 0
