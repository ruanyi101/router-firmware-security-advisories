# Security Advisory: Pre-authentication buffer overflow in TRENDnet TEW-657BRM `mini_httpd`

**Status:** Research advisory draft — CVE not assigned or independently confirmed  
**Vendor:** TRENDnet  
**Product:** TEW-657BRM Wireless N ADSL2+ Modem Router  
**Hardware:** v1.0R  
**Affected firmware:** 1.00.1  
**Affected component:** `/usr/sbin/mini_httpd`  
**Weakness:** CWE-787 (Out-of-bounds Write); CWE-120 (Classic Buffer Overflow)  
**Access required:** Unauthenticated access to the router's web management service  
**Testing:** Static analysis of the firmware and re-hosted QEMU-MIPS userspace testing, as documented in the supplied research package  
**Physical-hardware confirmation:** Not available in the supplied materials  
**Vendor notification:** To be verified by the researcher; the source package contains a notification draft but no delivery acknowledgment

## Summary

An out-of-bounds write was identified in the HTTP request handling logic of the
TRENDnet TEW-657BRM firmware 1.00.1 `mini_httpd` daemon. During processing of
certain paths containing `.htm`, the daemon constructs a redirect using an
unbounded `sprintf` operation into a fixed-size global buffer. This operation
occurs before the normal HTTP Basic authentication check.

The supplied research notes document a crash, control of the program counter,
and execution of a benign test payload in a re-hosted QEMU-MIPS environment.
An unauthenticated attacker who can reach the management service may be able
to exploit this memory corruption for remote code execution. Exploitation on
physical hardware has not been established by the supplied evidence.

## Affected software and exposure

| Item | Observed or reported value |
| --- | --- |
| Vendor | TRENDnet |
| Model | TEW-657BRM |
| Hardware revision | v1.0R |
| Firmware version | 1.00.1 |
| Executable | `/usr/sbin/mini_httpd` |
| Service | HTTP web management, TCP/80 in the tested firmware |
| Authentication | The vulnerable redirect path is processed before HTTP Basic authentication |
| Default attack surface | LAN management interface; WAN reachability depends on device configuration |

No claim is made here about other firmware versions or hardware revisions.

## Technical root cause

The research package identifies a redirect-building path in `mini_httpd` that
is taken when an HTTP request target contains `.htm` under the relevant parser
conditions. The handler constructs a URL similar to:

```c
/* Simplified representation of the vulnerable behavior; not vendor source. */
sprintf(global_redirect_buffer, "/setup.cgi?next_file=%s", request_path);
```

The destination is a fixed-size buffer in global writable data. There is no
length restriction sufficient to ensure that the destination can contain the
constant prefix plus a long attacker-supplied path. An oversized request
therefore overwrites neighboring global data, including pointers subsequently
used by the daemon.

The source analysis locates the unbounded `sprintf` call in the code around
`0x004044b8` and describes subsequent accesses to affected global values.
The relevant behavior is distinct from `setup.cgi`: the string
`/setup.cgi?next_file=` is part of the constructed redirect, while the
memory-corruption sink resides in `mini_httpd` itself.

## Evidence from the supplied research package

The supplied `CVE-TBD-mini_httpd-preauth-rce/README.md` reports the following
observations from isolated firmware re-hosting:

1. A shorter `.htm` request path produced the normal authentication response
   (HTTP 401). An oversized `.htm` request path caused the daemon's child
   process to fail before authentication. A long path without the relevant
   `.htm` condition did not follow the same vulnerable branch.
2. A debugger captured the memory corruption, including an attacker-influenced
   global pointer and a crash in the affected instruction sequence.
3. A separate debugger capture showed `pc = 0x23232323` and
   `t9 = 0x23232323`, demonstrating control of the emulated program counter
   as reported by the researcher.
4. A benign MIPS test payload wrote a marker to the emulated daemon's
   standard error and exited; the reported process exit code was `255`.

These findings go beyond a simple denial-of-service crash in the emulated
environment, but they **do not** constitute a verified exploit on a physical
router. The research archive supplies the technical narrative and proof-of-
concept scripts; it does not include a separate, independently authenticated
record of every interactive debugger session.

## Security impact

- **Confidentiality / integrity:** Potential arbitrary code execution in the
  web server's security context if the emulated control-flow conditions also
  hold on the physical device. The firmware analysis describes the web server
  as running with root privileges.
- **Availability:** An oversized unauthenticated request was reported to
  crash the web server process in re-hosted testing.
- **Attack prerequisites:** Access to the router's web management interface.
  Exposure to untrusted Internet hosts depends on remote management settings.
- **Scope limitation:** Only the stated firmware and emulation environment
  were assessed in the submitted research materials.

No CVSS base score is asserted as independently validated in this advisory.
Any eventual rating should take the actual exposure conditions and final
verification findings into account.

## Relationship to known reports

This issue concerns the `mini_httpd` HTTP parser before authentication, not
the previously documented post-authentication `setup.cgi` injection or
overflow issues in the same product. The TRENDnet legacy-product advisory
lists those known issues separately:

https://www.trendnet.com/langpo/support/view.asp?cat=4&id=107

A final duplicate review by VulDB/the responsible CVE Numbering Authority
is still required.

## Remediation and defensive guidance

The TEW-657BRM is an end-of-life product and no vendor fix was identified in
the supplied materials. Organizations should prioritize replacement with a
currently supported device. Pending replacement:

- Disable WAN-side remote management.
- Restrict access to HTTP management to a trusted management network.
- Avoid exposing the administrative interface to untrusted hosts.
- Monitor for unusual requests to the management endpoint and device
  instability.

These are exposure-reduction measures, not a patch.

## Disclosure and attribution

**Research source:** User-supplied TRENDnet TEW-657BRM firmware research
package prepared in October 2026.  
**Researcher / contact:** To be supplied by the person responsible for this disclosure.  
**Vendor contacted:** Unverified from the supplied files.  
**CVE status:** No identifier should be claimed before official assignment.  
**Publication status:** Draft for coordination and editorial review.

## Evidence availability

A non-weaponized evidence summary is included in this repository. The
original research archive contains additional PoC source that is deliberately
**not** included in this publication-oriented report. Technical evidence can
be provided privately to the vendor or CNA after verification of the
recipient and any applicable disclosure arrangements.
