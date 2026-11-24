# [CVE-TBD] Stack Buffer Overflow in setWAN (pppUserName) in Edimax BR-6428nS V2

## VulDB Submission Fields

- Vendor: Edimax
- Product: BR-6428nS V2
- Version or Commit: 1.16
- Vulnerability: Out-of-bounds Write (CWE-787)
- Advisory / Exploit URL: replace this with the URL of this directory after copying it to your public repository
- Description:

```
A stack buffer overflow vulnerability was discovered in Edimax BR-6428nS V2 firmware v1.16. The setWAN handler of the /bin/webs web server copies the attacker-controlled pppUserName POST parameter with an unbounded strcpy into a stack buffer when the companion wanMode parameter equals 2, and the binary is built without stack canaries. Reproduction: a single POST to /goform/setWAN with wanMode=2 and a 128-byte pppUserName value terminates the root single-process web server, while the identical request with 127 bytes is processed normally (threshold established by binary search, repeated). The request succeeds without credentials in the factory-default state, and in the configured state the default credentials are disclosed in the HTTP 401 authentication realm. An adjacent attacker can crash the management service remotely and repeatably; control-flow hijacking is plausible given the bug class but only the denial of service is claimed as demonstrated. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (6.5).
```

---

## Technical Disclosure

# CVE-TBD: Stack Buffer Overflow in setWAN (pppUserName) in Edimax BR-6428nS V2

## Summary

A stack-based buffer overflow was discovered in the Edimax BR-6428nS V2 router
firmware v1.16. The `setWAN` handler of `/bin/webs` copies the attacker-
controlled `pppUserName` POST parameter into a stack buffer with an unbounded
`strcpy()` when `wanMode=2` (PPPoE). The exact crash threshold was measured at
**128 bytes** (127 survives / 128 kills the process); the web server runs as
root, is single-process, and is built without stack canaries.

## Affected Product

- Vendor: **Edimax**
- Product: **BR-6428nS V2** (Realtek RTL8196C, MIPS32 BE)
- Firmware: **v1.16** (`BR6428NSv2_v1.16.bin`, SHA-256
 `93bcbbd9ea689ccbd3e69a835617eddba15dd7cba4233769e30dce2aae69b6c1`),
 latest and final release (verified 2026-10).

## Vulnerability Details

- Type: Out-of-bounds Write / classic buffer overflow (**CWE-787**)
- Component: `/bin/webs`, handler `setWAN` (function @ `0x00432870`)

### Root cause (decompiled, Ghidra)

```c
// setWAN(), PPPoE branch
v = websGetVar(wp, "wanMode", "");
if (atoi(v) == 2) {
 user = websGetVar(wp, "pppUserName", "");
 strcpy(local_140, user); // unbounded strcpy into stack buffer
 ...
}
```

The branch requires the companion parameter `wanMode=2`; without it the copy
is not reached (which is why naive fuzzing that omits the mode parameter does
not trigger the bug). The MIPS epilogue of the function reloads the saved
return address directly (`lw ra, …(sp); jr ra`) with **no stack canary**, and
the same binary's function prologue/epilogue pattern was confirmed by
instruction-level tracing of the analogous `formPPTPSetup` overflow
(qemu `-d in_asm` capture of the `jr ra` to a corrupted address).

### Authentication context

Factory-default state: no authentication (unauthenticated reachability).
Configured state: Basic auth with default credentials disclosed in the 401
realm (`Default Name:admin Password:1234`) — so the practical precondition is
"unchanged default password" unless the operator rotated it.

## Proof of Concept (non-destructive crash demonstration)

Isolated rehosted environment; the same request kills the web service on the
device until it restarts.

```bash
# crash (128 bytes) — with default credentials in the configured state
curl -u admin:1234 -X POST http://<device>/goform/setWAN \
 --data-urlencode "pppUserName=$(python3 -c 'print("A"*128)')" \
 --data "wanMode=2"
# -> HTTP response completes, then the single-process web server dies
# (observed: process termination; service recovers only after restart)

# control (127 bytes) — identical request one byte shorter
curl -u admin:1234 -X POST http://<device>/goform/setWAN \
 --data-urlencode "pppUserName=$(python3 -c 'print("A"*127)')" \
 --data "wanMode=2"
# -> normal error page, service alive
```

**Measured threshold (binary-searched, repeated):** safe ≤ 127 bytes,
crash ≥ 128 bytes; 877–4096 bytes all crash. Requests of 16 KiB are rejected
at the HTTP layer before the handler (not a security boundary, documented for
reproducibility). In the factory-default state the same requests succeed
without any credentials.

## Impact

An adjacent attacker can remotely crash the root web-management process
(reliable denial of service, repeatable at will). Beyond the measured crash,
the bug class (unbounded `strcpy` into a stack frame without canary on a
fixed-address MIPS binary) makes control-flow hijacking technically plausible;
consistent with responsible scoring, the CVSS below reflects the **demonstrated**
impact only. Two sibling handlers were confirmed to carry the same
copy-paste pattern with a different sink (`formPPTPSetup`/`formL2TPSetup`,
strcat-based, threshold 877) — those are already covered by CVE-2026-8776 /
CVE-2026-8775; this advisory covers `setWAN`/`pppUserName`, a distinct handler,
parameter and sink.

## CVSS 3.1

`AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — **6.5 (Medium)**
(Adjacent, unauthenticated in factory state, demonstrated availability impact.)

## Discovery

Vendor notified: pending.
