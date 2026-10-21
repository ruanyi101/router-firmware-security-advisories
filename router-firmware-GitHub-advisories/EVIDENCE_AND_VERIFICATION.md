# Evidence, provenance, and limitations

These writeups are **edited advisory drafts** prepared from two ZIP archives
supplied by the researcher:

- `TEW-657BRM_CVE披露材料包_20261013.zip`
- `DIR-600L_CVE提交材料_2026-10-13.zip`

The DIR-600L contents duplicated across the archives were counted once.

No new dynamic tests have been run while preparing this repository.
The editor has not authenticated the original researcher's identity,
device ownership, firmware acquisition process, vendor contact,
or the existence of any previously submitted CVE requests.

| Finding | Evidence present in supplied archive | What is not proven |
| --- | --- | --- |
| TEW mini_httpd | reverse-engineering writeup, described GDB PC snapshot, benign MIPS payload result, PoC source | independent raw debugger-session audit, physical-router confirmation |
| TEW upgrade_flash.cgi | disassembly, observed saved-RA overwrite / PC marker in emulation, disclosed hardware-check patches | unmodified physical-router RCE |
| DIR authentication.cgi | `strace` SIGSEGV with `si_addr=0x47474747`, handler source analysis | actual PC value, physical-device RCE |
| DIR HNAP SOAPAction | `strace` SIGSEGV with `si_addr=0x45454545`, separate CPU dumps | synchronized PC-on-crash proof, physical-device RCE |
| DIR gena command injection | emulator test marker transcript, function-flow analysis | physical-device confirmation, root-cause distinctness from prior CVEs |
| DIR hedwig traversal | XML config response in emulation, call-chain analysis | unrestricted arbitrary-file read, populated secret disclosure |

**Sensitive data handling:** This publication-ready package intentionally
does not include full exploit scripts, original firmware binaries, repository
metadata containing internal hostnames or developer identifiers, or
actual customer configuration dumps. The original evidence should be
shared privately with authorized vendor/CNA reviewers when necessary.

**Vendor contact note:** The original documents contain statements such as
"vendor notified 2026-10-13", but no independent delivery
receipt was verified in this preparation. Each reporter must confirm
their own notification history before asserting it publicly or
checking the VulDB "Request a CVE" prerequisite.
