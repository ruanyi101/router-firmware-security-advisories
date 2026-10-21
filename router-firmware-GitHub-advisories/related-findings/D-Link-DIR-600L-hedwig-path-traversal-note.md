# Additional affected-version research note: D-Link DIR-600L `hedwig.cgi` path traversal

**Purpose:** Existing-issue comparison / affected-product information;
not proof of unrestricted arbitrary file read.

**Product:** DIR-600L, hardware revision B, firmware 2.17b02  
**Weakness:** CWE-22 (Path Traversal); information exposure  
**Component:** `hedwig.cgi` -> `fatlady.php`, `service` value

The research package describes construction of an existing `.php` template
path from a caller-controlled `service` value, without sufficient
rejection of parent-directory path components. The analyzed CGI path did
not require a valid authenticated session for the observed operation.

A re-hosted qemu-mipsel test returned a rendered wireless
configuration tree by loading an existing configuration-export
template. The supporting XML capture contains SSIDs and settings with
authentication mode `OPEN` and encryption mode `NONE`.

**Confirmed scope:** Traversal to load certain accessible existing PHP
templates and disclosure of their rendered output in the test environment.

**Not confirmed:** Reading arbitrary non-PHP files with no restrictions;
recovery of a populated Wi-Fi password; extraction of any real user's
production credentials; physical-device exploitation.

A close prior is CVE-2024-0769 (DIR-859 `hedwig.cgi` path traversal).
The responsible CNA should decide whether the DIR-600L firmware is
an additional affected product or represents a distinct root cause.

**Source:** Supplied DIR-600L package,
`CVE-TBD-hedwig-cgi-service-path-traversal/README.md`.

**Public reference:** https://nvd.nist.gov/vuln/detail/CVE-2024-0769
