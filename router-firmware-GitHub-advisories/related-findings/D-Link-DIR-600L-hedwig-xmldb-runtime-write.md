# Research Note: Unauthenticated XMLDB Runtime-Node Modification via D-Link DIR-600L hedwig.cgi

**Publication status:** Supplemental technical report; avoid separate CVE request pending root-cause review. **CVE:** Not assigned. **Assessment:** The unauthenticated `hedwig.cgi` configuration path is previously known in related models; this report documents an additional runtime-write behavior observed on DIR-600L Rev B.

## Affected product

| Item | Detail |
| --- | --- |
| Vendor | D-Link |
| Product | DIR-600L hardware revision B |
| Firmware examined | 2.17b02 |
| Components | `hedwigcgi_main` in `htdocs/cgibin`; `xmldbc_read` |
| Weakness | Missing authentication (CWE-306); insufficient XML structure validation (CWE-20 / CWE-91 candidate) |
| Affected resource | In-memory `/runtime` configuration database subtree |

## Summary

The `hedwig.cgi` configuration-processing pathway accepts data associated with an unverified cookie-supplied session identifier. The research demonstrated that this data could be merged into the router's runtime configuration database, and that malformed but well-formed-at-the-document-level XML structure could move the resulting update outside the intended session subtree.

## Technical explanation

The analyzed handler obtains a `uid` cookie value without confirming the user session. It then creates an XML wrapper incorporating a caller-controlled request body and passes the resulting document to the configuration database parser. The parser merges data into the `/runtime` tree.

In the reported test, carefully structured XML altered the normal tree nesting and caused a marker to be stored in a sibling node under `/runtime`, rather than only under `/runtime/session/<uid>/postxml`. The immediate security issue is integrity compromise of runtime state without authentication. The source notes explicitly limit verified writes to **ordinary nodes under `/runtime`**, not arbitrary filesystem files or persistent flash configuration.

This report intentionally omits a directly usable XML-injection request body.

## Verification evidence

The source package contains `hedwig_poc_transcript.txt`, recording a successful handler response and a subsequent database read showing a marker value (`PWN3`) in `/runtime/evilC`. It also describes a normal session-subtree update performed with an arbitrary cookie value and no established session.

The follow-up novelty review documents restrictions: certain attribute-bound nodes rejected writes, and multi-root XML documents were rejected by the parser. The supplied evidence does **not** demonstrate a reliable stored command-execution exploit, a persistent configuration rewrite, or full router compromise.

## Impact and severity

Confirmed in the research environment: unauthorized integrity modification of selected runtime configuration nodes. The original research proposes **CVSS v3.1 4.3 (Medium)**, vector `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`, limited to the observed integrity effect. Claims about a subsequent administrator-triggered exploit chain should remain hypotheses pending proof and should not increase the severity score without testing.

## Prior art / assignment recommendation

The lack of session verification in `hedwig.cgi` and related configuration-processing behavior has been publicly discussed in older D-Link research, including the DIR-850L family. The original archive's later `novelty.md` **downgraded** this finding from an independent novel root cause to a supplemental write-side confirmation. Accordingly, use this report to support coordinated disclosure or an existing related entry, not as a definitive new CVE claim.

Related reference for the traversal aspect of the same feature family: https://nvd.nist.gov/vuln/detail/CVE-2024-0769

## Mitigation and disclosure

Validate authenticated sessions, strictly separate untrusted XML from privileged wrapper structure, and constrain database writes to an authorized session namespace. Retire unsupported products and limit web management to trusted hosts.

This note reflects QEMU-MIPSEL re-hosted validation and original research dated **2026-10-12**. Physical-device behavior and vendor-contact status remain unverified.
