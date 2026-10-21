# Affected-Model Research Advisory: hedwig.cgi Service Path Traversal on D-Link DIR-600L Rev B

**Publication status:** Coordinated-disclosure / affected-product report. **CVE:** No separate identifier established. **Assessment:** Related-root-cause finding; report DIR-600L Rev B as a newly observed affected variant rather than assert discovery of a wholly new vulnerability.

## Affected product

| Item | Detail |
| --- | --- |
| Vendor | D-Link |
| Product | DIR-600L |
| Hardware | Revision B |
| Firmware examined | 2.17b02 |
| Components | `hedwig.cgi` and `/htdocs/webinc/fatlady.php` |
| Weakness | Path traversal (CWE-22), information exposure (CWE-200), missing authentication (CWE-306) |
| Entry point | HTTP configuration-processing request; no valid session required in researcher testing |

## Summary

The firmware passes a client-supplied service identifier into a PHP file-path construction operation without sufficiently restricting traversal components. Because the associated configuration handler accepts input without verifying an active session, the researcher was able to cause an existing configuration-export template to run and return configuration data in an unauthenticated HTTP response.

## Technical explanation

The service handler forms a path under a `fatlady` module directory by concatenating a user-supplied service name with a PHP filename suffix. The researcher's static review found no adequate traversal filtering. Separately, the `hedwig.cgi` handler obtains a cookie-supplied session identifier without validating that the corresponding session is authenticated.

The combination permits access to existing server-side PHP templates outside the intended module path. This is a restricted local-file-include class of bug involving PHP templates; the supplied evidence **does not prove unrestricted reading of arbitrary operating-system files**.

## Verification evidence

The source archive includes `wifi_config_disclosure.xml`, a response capture produced in the re-hosted QEMU-MIPSEL environment. The researcher reported an unauthenticated request that caused a configuration-export template to produce the `/wifi` tree. The captured tree showed SSIDs, wireless modes, encryption settings, and WPS/ACL policy. In the included capture, the shown networks were open; **the supplied capture did not demonstrate disclosure of a configured WPA password**.

The research notes describe additional template-based reads of account and DDNS-related configuration. Account password fields were reported as masked when set; therefore the claim that an administrator password was recovered in plaintext is **not supported** by the supplied capture. Credentials could potentially be exposed when stored in other unmasked configuration trees, depending on real configuration state.

**Evidence limitation:** The observed result was obtained in an emulated router environment; a physical-device validation log is not included.

## Impact and severity

A network client with access to the vulnerable HTTP endpoint can obtain configuration information that should require administrative privileges. The original report proposes `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (**6.5, Medium**), but a CNA may reasonably adjust confidentiality impact based on which sensitive fields are verified readable.

## Related disclosures / duplicate assessment

The root-cause pattern strongly resembles **CVE-2024-0769** (D-Link DIR-859 `hedwig.cgi` service traversal) and prior public work on other DIR-series routers. This report contributes an apparent **DIR-600L Rev B firmware 2.17b02 affected-product confirmation**. Do not request a fresh CVE solely because the affected model differs.

Reference: https://nvd.nist.gov/vuln/detail/CVE-2024-0769

## Remediation and disclosure

Require valid sessions before processing configuration requests, allowlist service names, and use canonical path validation that confines file access to the intended directory. Restrict management access and retire unsupported hardware.

The original notes date discovery to **2026-10-12**. Vendor notification has not been independently confirmed. Sensitive full configuration captures are excluded from this public-facing report.
