# Affected-Model Research Advisory: Unauthenticated GENA Command Injection on D-Link DIR-600L Rev B

**Publication status:** Coordinated-disclosure draft. **CVE:** New identifier not established. **Assessment:** Strong evidence of a vulnerable model, but highly related to existing GENA command-injection disclosures; seek CNA duplicate/affected-product guidance before requesting a separate CVE.

## Affected product

| Item | Detail |
| --- | --- |
| Vendor | D-Link |
| Product | DIR-600L |
| Hardware | Revision B |
| Firmware examined | 2.17b02 (research binary `DIR-600Bx_FW217b02.bin`) |
| Component | `genacgi_main` / GENA subscription handler in `htdocs/cgibin` |
| Weakness | OS command injection (CWE-78) |
| Entry point | UPnP GENA subscription processing; unauthenticated according to the original analysis |

## Summary

Static analysis identified a GENA subscription handler that incorporates untrusted `service` data into a command string handed to an execution-capable timer facility. Dynamic testing reported execution of a benign marker command in a re-hosted MIPSEL firmware environment, without any valid web session. The researcher reported root-context execution in the emulated firmware service configuration.

## Technical explanation

The affected logic processes the `service` parameter of a GENA subscription. Instead of validating the service identifier against an allowed set and treating it only as data, the handler interpolates it into a shell-oriented timer operation associated with a temporary notification script. The command is subsequently processed by the `xmldb` service. Shell-significant characters can therefore alter the operation performed by the service.

The research notes distinguish the physical device's LAN-facing UPnP service from the re-hosted test route: the latter mapped the handler into a different HTTP document-root configuration, but used the same analyzed handler code. Reachability on actual routers was inferred from firmware service configuration, not independently network-tested on hardware.

This public summary deliberately does not reproduce the command-injection string or an immediately executable exploitation request.

## Verification evidence

The source archive includes `gena_rce_transcript.txt`, which records an HTTP 200 response and the creation of a marker file containing `PWNED_GENA_FINAL` in the emulated environment. The static-analysis report connects the untrusted service parameter to the executable timer operation. The transcript does not itself include an independent privilege-context attestation; the root-context assessment comes from the accompanying firmware analysis.

**Evidence limitation:** Execution was recorded in user-mode QEMU re-hosting, not on the physical DIR-600L device. The public evidence supports a serious code-execution risk for reachable vulnerable firmware, while actual deployment exposure and exploit reliability on hardware remain untested here.

## Impact and severity

An unauthenticated client that can reach the affected UPnP service may be able to run commands with service privileges. The original research proposes **CVSS v3.1 8.8 (High)** using `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, assuming the vulnerable service is reachable from the adjacent network and has high privilege.

## Related disclosures and CVE handling

This finding is closely related to **CVE-2019-17621**, a documented unauthenticated command injection affecting D-Link DIR-859 through a GENA endpoint. Other family variants have also been reported. The original researcher did not find DIR-600L Rev B explicitly named in the compared affected-product lists as of October 2026. That does not establish a new root cause or guarantee a new CVE. Prefer an **affected-model extension / coordinated vendor report** unless a CNA determines the variant requires a new record.

References:
- D-Link SAP10147: https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10147
- CISA CVE-2019-17621: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## Remediation and disclosure

Isolate or disable UPnP exposure where practicable; restrict management and local-network access, and replace unsupported firmware or hardware. Service identifiers must never be interpolated into shell commands.

The original files date discovery to **2026-10-12**. The vendor-notification status is **not independently verified**. Coordinate with D-Link before any detailed public disclosure.
