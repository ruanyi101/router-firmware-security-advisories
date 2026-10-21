# Security Advisory Draft: Unauthenticated Subversion Metadata Disclosure in TRENDnet TEW-657BRM

**Publication status:** Draft for coordinated disclosure. **CVE:** Not assigned or independently confirmed. **Assessment:** Potential standalone candidate after current duplicate and vendor-notification checks.

## Affected product

| Item | Detail |
| --- | --- |
| Vendor | TRENDnet |
| Product | TEW-657BRM Wireless N ADSL2+ Modem Router |
| Hardware revision | v1.0R |
| Firmware examined | 1.00.1 |
| Component | Static-content handling by `mini_httpd` |
| Exposed firmware artifact | `/usr/www/images/.svn/entries` |
| Weakness | Information exposure (CWE-200); externally accessible file (CWE-552) |
| Authentication | Not required for the affected static-content subtree, according to the research records |

## Summary

The firmware image contains Subversion working-copy metadata in a directory served by the embedded HTTP server without authentication. Consequently, a network client able to access the web management service may retrieve development metadata that should not have been included in a production firmware image. This is an information-disclosure issue, not direct evidence of device takeover.

## Root cause and attack surface

Static firmware analysis located a Subversion metadata file beneath `/usr/www/images/`. The research records indicate that `mini_httpd` permits unauthenticated reads of static resources beneath `/images/` while authentication is required for many other routes. The build artifact is therefore exposed through the static content serving mechanism rather than through a password or administrative configuration endpoint.

The researcher described the metadata as containing an internal source-code repository address, a developer account identifier, workspace paths, and a file inventory. Internal addresses, account names, and the raw file content are intentionally omitted from this public-facing draft.

## Verification evidence

The supplied research report describes testing in a re-hosted QEMU-MIPS firmware environment:

- Access to `/images/.svn/entries` produced an HTTP 200 response with a reported 10,629-byte metadata body.
- A comparison request to `/.svn/entries` returned HTTP 401.
- Firmware filesystem inspection located the metadata under the publicly served image directory.

**Evidence limitation:** The archive contains the original research narrative but not an independently authenticated packet capture or the entire metadata response. These observations are reproduced here as researcher-reported results, not as tests independently rerun for this advisory. No physical-device reproduction has been supplied.

## Impact and severity

An unauthenticated client on a network that can reach the management interface may learn development infrastructure details and the layout of the shipped web-content tree. This may aid reconnaissance and follow-on targeting; no router credentials or successful device compromise are evidenced by this issue alone.

The original research proposes **CVSS v3.1 4.3 (Medium)**, vector `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`. This is a preliminary assessment for a default LAN-adjacent deployment, not a CNA-assigned score.

## Remediation guidance

Exclude `.svn` and other version-control metadata from firmware release images. Add an explicit deny rule for hidden version-control directories, and limit router management access to trusted hosts and networks. Owners of unsupported devices should evaluate retirement or replacement.

## Disclosure, duplication, and research provenance

The original notes date discovery to **2026-10-12** and record a vendor-notification claim for **2026-10-13**. The notification's actual delivery and receipt have **not** been independently verified. Confirm notification and run a fresh CVE/VulDB duplicate search before requesting a new identifier.

This report is based on researcher-provided firmware analysis and re-hosted test results. It contains no raw sensitive vendor development metadata.
