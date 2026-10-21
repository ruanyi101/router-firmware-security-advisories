# Router Firmware Security Research Advisories

**Status:** Editorial drafts prepared from researcher-supplied archives.  
**Disclosure:** Coordinate with the affected manufacturers and CVE Numbering
Authorities before changing this repository to public.  
**CVE identifiers:** None are claimed by this repository.

This repository contains vulnerability advisory drafts covering two
end-of-life router firmware families. The reports preserve
verified-in-source technical observations while distinguishing
firmware-emulation results from confirmation on physical hardware.

## Priority advisory drafts

| Product / firmware | Finding | Scope documented | Advisory |
| --- | --- | --- | --- |
| TRENDnet TEW-657BRM 1.00.1 | `mini_httpd` pre-authentication buffer overflow | PC control and benign test-code execution reported in emulation | [Read advisory](advisories/TRENDnet-TEW-657BRM-mini_httpd.md) |
| TRENDnet TEW-657BRM 1.00.1 | `upgrade_flash.cgi` stack overflow | PC control in a disclosed patched test harness | [Read advisory](advisories/TRENDnet-TEW-657BRM-upgrade_flash.md) |
| D-Link DIR-600L rev B 2.17b02 | `authentication.cgi` stack overflow | CGI SIGSEGV; program-counter control not yet established | [Read advisory](advisories/D-Link-DIR-600L-authentication-cgi.md) |
| D-Link DIR-600L rev B 2.17b02 | HNAP `SOAPAction` stack overflow | CGI SIGSEGV; program-counter control not yet established | [Read advisory](advisories/D-Link-DIR-600L-HNAP-SOAPAction.md) |

## Related findings requiring CVE/root-cause comparison

- [DIR-600L GENA command-injection observation](related-findings/D-Link-DIR-600L-gena-command-injection-note.md)
- [DIR-600L hedwig path-traversal observation](related-findings/D-Link-DIR-600L-hedwig-path-traversal-note.md)

These **are not automatically separate CVEs**: similar vulnerabilities
are already recorded for other D-Link firmware products.

## Review and source material

- [Evidence inventory and limitations](EVIDENCE_AND_VERIFICATION.md)
- [VulDB field-filling reference](VULDB_FIELDS_CN.md)
- [GitHub upload and disclosure instructions (Chinese)](GITHUB_UPLOAD_CN.md)

This repository intentionally omits operational weaponized exploitation
scripts. Original, more detailed research material can be supplied to
authorized reviewers through coordinated channels.

## Public references

- [TRENDnet TEW-657BRM legacy security notice](https://www.trendnet.com/langpo/support/view.asp?cat=4&id=107)
- [CVE-2024-0769 — related D-Link hedwig traversal](https://nvd.nist.gov/vuln/detail/CVE-2024-0769)
- [CVE-2023-33626 — related D-Link gena overflow; check for duplication](https://nvd.nist.gov/vuln/detail/CVE-2023-33626)
- [VulDB Submission Policy](https://vuldb.com/kb/submission)

## Publication notes

Publication does not mean a CVE has been issued. Do not use a `CVE-2026-XXXX`
placeholder as if it were an assigned number. Replace the advisory's
vendor-contact status only once a real contact receipt has been retained.
