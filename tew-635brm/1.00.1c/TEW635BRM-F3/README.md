# [CVE-TBD] TRENDnet TEW-635BRM 1.00.1C External Control of File Name or Path (CWE-73)

## VulDB Submission Fields

- Vendor: TRENDnet
- Product: TEW-635BRM
- Version or Commit: 1.00.1C
- Vulnerability: External Control of File Name or Path (CWE-73)
- Advisory / Exploit URL: replace this with the URL of this directory after copying it to your public repository
- Description:

```
An arbitrary file write vulnerability was discovered in TRENDnet TEW-635BRM (hardware v1.0R) firmware V1.0(1.00.1C). The hidden action vi_save of /usr/sbin/setup.cgi (0x0040f60c, not linked from any menu) forwards the attacker-supplied POST parameters savetopath and outlog_Display to the root daemon cmd_agent_ap via the /tmp/cmd_agent FIFO, which then executes the primitive ECHO=<path>=:<content>, overwriting the file <path> with <content> as root. The only precondition besides web authentication is that the target file already exists (an access() check); the POST parameter parser performs no character filtering at all, so arbitrary content including shell metacharacters and newlines can be written. Reproduction: curl -u admin:password -X POST http://<router>/setup.cgi --data-urlencode todo=vi_save --data-urlencode next_file=system_command.htm --data-urlencode savetopath=/tmp/vitest --data-urlencode outlog_Display=PWNED_BY_VI_SAVE returns HTTP 200 and /tmp/vitest contains exactly the marker content, written by root; a control request with a non-existent path changes nothing, confirming the access() gate. An authenticated attacker (the device ships with factory credentials admin:password) can overwrite configuration databases, startup scripts and credential files as root; chained with any command-execution primitive (e.g. the system_command action confirmed on this product) the existence restriction is lifted via touch, resulting in unrestricted root file write and reliable persistence. Proposed CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8).
```

---

## Technical Disclosure

# CVE-TBD: TRENDnet TEW-635BRM setup.cgi Hidden `vi_save` Action — Authenticated Arbitrary File Write as root

## Affected Product

- Vendor: TRENDnet
- Product: TEW-635BRM (hardware revision v1.0R)
- Firmware: V1.0(1.00.1C) — latest version available for this hardware revision (published 2010-06-18 on downloads.trendnet.com)
- Component: `/usr/sbin/setup.cgi` (web management CGI) → `/tmp/cmd_agent` FIFO → `/usr/sbin/cmd_agent_ap` (root daemon)

## Summary

`setup.cgi` implements a hidden action `vi_save` (not linked from any
menu) that forwards the attacker-supplied parameters `savetopath` and
`outlog_Display` to the root daemon `cmd_agent_ap`, which then executes
the primitive `ECHO=<path>=:<content>` — overwriting the file `<path>`
with `<content>` **as root**. The only precondition besides web
authentication is that the target file already exists (an `access()`
check). Combined with the device's command-execution surface (e.g. the
`system_command` action or the pre-auth UPnP injection), the existence
restriction can be lifted, yielding **arbitrary-file arbitrary-content
write as root**. The POST parameter parser performs no character
filtering at all, so arbitrary file content (including shell
metacharacters and newlines) can be written.

## Vulnerability Type / CWE

- CWE-73: External Control of File Name or Path

## Root Cause

Decompiled `vi_save` (setup.cgi, 0x0040f60c):

```c
path = find_val(req, "savetopath"); // no validation
content = find_val(req, "outlog_Display"); // no validation / no filtering
if (access(path, F_OK) == 0) { // only constraint: file must exist
 COMMAND("ECHO=%s=:%s", path, content); // → vsnprintf → /tmp/cmd_agent FIFO
}
```

`cmd_agent_ap` (root, started by init) reads the FIFO and implements the
`ECHO=` primitive by opening `<path>` for writing and storing `<content>`.
The CGI-to-daemon relay exists to give the web UI root privileges; the
daemon performs no authentication or sanity checking of its own.

## Proof of Concept (non-destructive)

```bash
# create the marker target first (e.g. via touch on a test device), then:
curl -s -u admin:password -X POST http://<ROUTER_IP>/setup.cgi \
 --data-urlencode "todo=vi_save" \
 --data-urlencode "next_file=system_command.htm" \
 --data-urlencode "savetopath=/tmp/vitest" \
 --data-urlencode "outlog_Display=PWNED_BY_VI_SAVE"
```

Observed on the rehosted firmware: HTTP 200, and inside the device
`/tmp/vitest` (previously created empty) contains exactly
`PWNED_VI_SAVE_1791815310` (timestamped marker), written by root.
Control requests with a non-existent `savetopath` leave the filesystem
untouched (the `access()` gate), confirming the code path.

## Impact

- Authenticated attacker (or anyone able to reach the authenticated
 surface — the device ships with factory credentials `admin:password`)
 overwrites arbitrary existing files as root: configuration databases,
 startup scripts, cron entries, password/shadow files, firmware-update
 artifacts.
- Chained with any command-execution primitive (e.g. the `system_command`
 action confirmed on this product, or the pre-auth UPnP injection), the
 "file must exist" restriction is removed (`touch`), resulting in
 unrestricted root file-write → reliable, stealthy persistence and
 full device takeover.
- The web process and the helper daemon both run as root; there is no
 integrity verification anywhere in the chain.

## Proposed CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` — **8.8 (High)**

## Discovery

- Date: 2026-10-12
- Method: firmware rehosting (QEMU full-system emulation) + static reverse engineering (Ghidra) + dynamic verification

## Timeline

- 2026-10-12: Vulnerability discovered and verified (root file overwrite with marker content)
- 2026-10-13: Vendor notification sent
- TBD: CVE ID assignment
- TBD: Public disclosure

## Proof of Concept

See the poc file(s) in this directory.
