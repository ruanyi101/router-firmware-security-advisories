# Security Advisory: Stack buffer overflow in D-Link DIR-600L HNAP SOAPAction handling

**Status:** Draft; CVE not assigned or confirmed  
**Product:** D-Link DIR-600L, hardware revision B, firmware 2.17b02  
**Component:** `hnap_main` in `htdocs/cgibin`  
**Weakness:** CWE-121 (Stack-based Buffer Overflow)  
**Access:** Pre-authentication HNAP handler path, as described by supplied analysis  
**Testing:** Re-hosted qemu-mipsel CGI environment

## Summary

The HNAP `hnap_main` handler derives an action name from the
client-supplied HTTP `SOAPAction` header and uses that value in
unbounded operations targeting a local stack buffer. The analysis
describes a 256-byte destination and multiple string-formatting/copy
sites. The vulnerable code path was reportedly reached without
valid credentials because the action whitelist check could be
satisfied separately from the attacker-controlled action suffix.

## Observed evidence

The supplied `strace_hnap_overflow.log` captures a crashing CGI child:

```text
SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_ACCERR, si_addr=0x45454545}
```

The additional CPU-state records and length-sweep discussion are
consistent with attacker-influenced memory corruption in emulation.
The supplied `si_addr` does not by itself prove that PC was set to
`0x45454545`. A synchronized PC/RA snapshot is still required before
asserting confirmed control-flow hijack. The archive does not
demonstrate arbitrary code execution on a physical router.

## Relationship to other reports

This is a memory-copy weakness in the HNAP action handler rather than
the HNAP shell-command injection issue already described for D-Link
devices. Other D-Link models have had similar HNAP `SOAPAction`
memory-corruption reports (for example CVE-2021-43722 in DIR-645);
the precise code root cause must be compared before requesting a new
identifier for this device.

## Impact, mitigation and disclosure

The demonstrated effect is CGI memory corruption and child-process
denial of service in an emulated environment. Network exposure
depends on management configuration. Replace unsupported devices
or strictly isolate administrative interfaces.

Vendor contact and CVE status remain to be verified. Source:
`cve_submission/github_repo/CVE-TBD-hnap-soapaction-stack-overflow/`
in the supplied DIR-600L archive.
