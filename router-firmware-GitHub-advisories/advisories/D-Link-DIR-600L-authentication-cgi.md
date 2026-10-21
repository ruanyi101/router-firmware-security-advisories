# Security Advisory: Pre-authentication stack buffer overflow in D-Link DIR-600L `authentication.cgi`

**Status:** Draft; CVE not assigned or confirmed  
**Product:** D-Link DIR-600L, hardware revision B, firmware 2.17b02  
**Component:** `authentication.cgi` in `htdocs/cgibin`  
**Firmware image recorded in research:** `DIR-600Bx_FW217b02.bin`  
**Firmware MD5 recorded in research:** `2f953ec274caeab6bc643045da56ab29`  
**Weakness:** CWE-121 (Stack-based Buffer Overflow)  
**Access:** Unauthenticated web request, LAN management interface in the tested scenario  
**Testing:** Re-hosted qemu-mipsel CGI environment

## Summary

The login handler processes the user-controlled `id` and `password`
parameters using unbounded `strcpy` operations before completing
authentication. The supplied analysis identifies fixed-size stack
buffers in the relevant handler. An excessively long login parameter
can corrupt adjacent stack memory.

## Observed evidence

The original archive contains a host-side
`strace_authentication_cgi.log` capture for an unauthenticated request.
The record includes:

```text
SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_ACCERR, si_addr=0x47474747}
```

This is an attacker-influenced fault address and demonstrates memory
corruption and a process crash in the emulated scenario. **A Linux
`siginfo.si_addr` value is not, by itself, proof of the program-counter
register's value.** A PC/RA register dump should be added before claiming
demonstrated instruction-pointer control or practical remote code execution.

The materials indicate that the forked CGI child crashed while the parent
HTTP daemon continued serving requests.

## Impact

The demonstrated impact is a pre-authentication memory-corruption
condition and crash of the login CGI child. System-wide denial of service,
physical-device code execution, and persistence are not established by
the submitted evidence. The affected function/input differ from older
published D-Link DIR-600L login findings and require a final duplicate
review.

## Remediation and disclosure

Replace end-of-life hardware and restrict management access. Vendor
notification and CVE assignment are to be confirmed. Source:
`cve_submission/github_repo/CVE-TBD-authentication-cgi-stack-overflow/`
from the supplied DIR-600L research archive.
