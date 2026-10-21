# Investigation Draft: Potential Stack Buffer Overflow in D-Link DIR-600L GENA Subscription Handler

**Publication status:** HOLD for duplicate/root-cause and debugger verification. **CVE:** Not assigned. **Assessment:** Do not request a separate CVE until compared with CVE-2023-33626 and stronger control-flow evidence is available.

## Affected product

| Item | Detail |
| --- | --- |
| Vendor | D-Link |
| Product | DIR-600L hardware revision B |
| Firmware examined | 2.17b02 |
| Component | GENA subscription routine in `htdocs/cgibin` |
| Weakness under investigation | Stack-based buffer overflow (CWE-121) |
| Reachability | Network GENA subscription processing; authentication not required according to static analysis |

## Summary

The researcher identified two formatting operations in the GENA subscription handler that place attacker-influenced input into a fixed-size stack buffer without a suitable bound. Long service values caused process termination in a re-hosted QEMU-MIPSEL environment. This may represent a stack buffer overflow, but the available evidence does not independently establish reliable program-counter control or a deployable code-execution path.

## Technical explanation

Static analysis of the subscription routine identified a local stack buffer approximately 516 bytes in size and command/script construction operations that can incorporate caller-controlled service and callback information. The source analysis suggests that oversized values may overwrite stack-adjacent data.

This suspected memory-safety issue is distinct in mechanism from the command-injection behavior described in a separate GENA advisory. However, distinct symptoms do not establish a separately assignable CVE if the same underlying overflow has already been documented elsewhere.

## Verification evidence

The supplied files include:

- `qemu_fatal.log`, reporting an uncaught target signal 11 / segmentation fault.
- `strace_gena_overflow.log`, showing `SIGSEGV`-related process termination in the re-hosted test.
- A research narrative reporting a crash near the handler epilogue following large service values.

**Evidence limitations:** The supplied host-side signal trace is not a validated guest CPU register dump, does not show a trustworthy attacker-chosen instruction pointer, and includes a user-generated signal indication. The claim that the saved return address was overwritten needs direct debugger corroboration. There is no physical-router test, proven denial of the overall HTTP service, or demonstrated remote code execution.

## Impact and severity

A CGI worker crash is reported and an unsafe boundedness pattern is suggested by static analysis. A concrete availability impact and CVSS score should be decided only after validating the true fault mechanism, user reachability, and service recovery characteristics. The source draft proposed **6.5 (Medium)** for a denial-of-service scenario; that value is **not independently confirmed** here.

## Duplicate assessment

**CVE-2023-33626** describes a `gena.cgi` stack overflow on D-Link DIR-600 hardware revision B5 running firmware 2.18. The original finding also uses an oversized GENA service value. Before asking for a separate identifier for DIR-600L Rev B firmware 2.17b02, compare the precise vulnerable function, formatting call, stack layout, affected field, and patch lineage. If they share a root cause, treat DIR-600L as an affected-product extension.

Reference: https://nvd.nist.gov/vuln/detail/CVE-2023-33626

## Remediation and disclosure

Bound all formatted writes by the size of the destination buffer and reject oversized callback and service values. Disable unnecessary UPnP exposure and replace unsupported routers.

Research record date: **2026-10-12**. Vendor notification status unverified. **This is an investigation draft, not a submission-ready claim of arbitrary code execution.**
