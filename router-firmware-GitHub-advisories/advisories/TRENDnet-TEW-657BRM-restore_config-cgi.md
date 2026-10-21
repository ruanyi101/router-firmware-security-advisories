# Security Advisory Draft: Multipart Parsing Out-of-Bounds Read in TRENDnet TEW-657BRM restore_config.cgi

**Publication status:** Research draft; hold for impact review. **CVE:** Not assigned or independently confirmed. **Assessment:** Low-priority standalone candidate if the service-availability impact and vendor notification can be substantiated.

## Affected product

| Item | Detail |
| --- | --- |
| Vendor | TRENDnet |
| Product | TEW-657BRM Wireless N ADSL2+ Modem Router |
| Hardware revision | v1.0R |
| Firmware examined | 1.00.1 |
| Binary | `/usr/sbin/restore_config.cgi` |
| Weakness | Out-of-bounds read (CWE-125); improper input validation (CWE-20) |
| Entry point | Authenticated configuration-restore upload |

## Summary

The firmware's configuration-restore handler scans a multipart request body for a header terminator without checking whether its read cursor remains within the input buffer. A malformed upload can cause the scan to read beyond the allocated stack buffer and terminate the CGI process in an isolated emulated environment.

## Technical explanation

The original reverse-engineering notes describe input handling that first searches for a multipart `Content-Disposition:` marker. After that marker is found, the handler enters a manually implemented byte loop looking for the sequence that separates multipart headers from content. The loop advances without a corresponding end-of-buffer bound. If the delimiter is missing, reads can continue past the original data and reach an unmapped address.

The presence check for `Content-Disposition:` itself is reported to be correctly null-checked; this issue concerns the subsequent delimiter scan. No unbounded write or overwrite of the return address was identified in this finding.

## Verification evidence

According to the research archive, a malformed body in a QEMU-MIPS re-hosted execution caused the CGI process to stop with `SIGSEGV`. The researcher's debugger summary identified a byte-load instruction in the scan loop and a pointer above the mapped stack boundary. Control bodies of the same approximate size either lacking the marker or containing a valid multipart terminator returned the normal error page.

**Evidence limitation:** The shared archive contains a source report and a test generator, but does not by itself establish that the complete router web-management service becomes unavailable. The confirmed observation described in the report is a CGI process crash in emulation; a durable denial of the HTTP service, repeated failure, or physical hardware impact is not confirmed.

## Impact and severity

An authenticated user able to submit a configuration-restore request may crash the CGI worker. Any broader availability loss is an inference requiring further testing. No confidentiality exposure, unauthorized data write, or reliable code execution was demonstrated.

The original draft proposes **CVSS v3.1 3.5 (Low)**, vector `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L`. This score assumes limited availability impact; review the availability metric if testing shows only an isolated worker-process crash without an externally meaningful outage.

## Remediation guidance

Reject malformed multipart bodies, enforce a strict bound while scanning for delimiters, and ensure all input parsing routines operate on explicit buffer lengths. Restrict configuration-restore functionality to authorized administrators and trusted management networks.

## Disclosure and related findings

The same firmware has a separate, more severe multipart-processing finding in `upgrade_flash.cgi`, documented independently. Similar parsing style does not automatically mean the two weaknesses share an assignable CVE. The original research notes date the finding to **2026-10-12** and claim vendor contact on **2026-10-13**; notification has not been independently checked.

This document is a vulnerability-research draft, **not a claim of physical-router denial of service**.
