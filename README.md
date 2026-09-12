# HVCI LOLDrivers Check — Updated

A PowerShell-based tool for comparing the **LOLDrivers vulnerable-driver database** against Microsoft's **Vulnerable Driver Blocklist**.

This project was originally forked from [`trailofbits/HVCI-loldrivers-check`](https://github.com/trailofbits/HVCI-loldrivers-check). The original project checks which LOLDrivers are blocked by the HVCI policy.

This version has been substantially updated to work with the current LOLDrivers API and Microsoft's downloadable Vulnerable Driver Blocklist format. It performs the comparison locally using the downloaded data rather than relying on the older policy-extraction workflow.

> **Purpose:** defensive security auditing and visibility into vulnerable drivers that are or are not represented by Microsoft's blocklist.

---

## Features

* Downloads the current LOLDrivers database automatically.
* Uses the LOLDrivers API directly.
* Filters the database to entries categorized as **`vulnerable driver`**.
* Downloads Microsoft's `VulnerableDriverBlockList.zip`.
* Extracts `DriverPolicy_Enforced.xml` automatically.
* Parses the Microsoft Code Integrity policy XML.
* Extracts Microsoft `Deny` file rules.
* Compares LOLDrivers against Microsoft deny rules.
* Performs SHA/MD5/SHA1 hash matching.
* Performs filename matching.
* Normalizes hashes before comparison.
* Displays matched and unmatched drivers.
* Generates a JSON report in `%TEMP%`.

---

## What This Tool Checks

The script compares two sources:

### LOLDrivers

The script downloads:

```text
https://www.loldrivers.io/api/drivers.json
```

It processes the database and keeps entries whose:

```text
Category = vulnerable driver
```

Other categories are ignored.

For each vulnerable-driver entry, the script collects:

* MD5
* SHA1
* SHA256
* Authentihash MD5
* Authentihash SHA1
* Authentihash SHA256
* Filename
* OriginalFilename

---

### Microsoft Vulnerable Driver Blocklist

The script downloads Microsoft's:

```text
VulnerableDriverBlockList.zip
```

It extracts:

```text
DriverPolicy_Enforced.xml
```

The XML is parsed as a Windows Code Integrity policy.

The script currently examines the policy's `FileRules` and extracts:

* `Deny` hash rules
* `Deny` filename rules
* Rule IDs
* Maximum file versions where present

---

## Matching Logic

A LOLDrivers entry is considered **matched** when one of its known hashes appears in Microsoft's deny rules.

Hash comparison is performed after normalization:

```text
lowercase/uppercase differences → ignored
spaces                      → ignored
-                           → ignored
:                           → ignored
```

For example, these representations are treated equivalently:

```text
AA-BB-CC
AA BB CC
aa:bb:cc
AABBCC
```

The script then performs a filename comparison if no hash match was found.

Filename comparison is case-insensitive.

---

## Important Interpretation

A driver appearing under:

```text
NOT in blocklist (gap)
```

does **not** automatically mean that the driver can successfully load on the current machine.

Other Windows security mechanisms can affect driver loading, including:

* Driver signature requirements
* HVCI configuration
* Windows version/build
* Driver architecture
* Code Integrity configuration
* Other endpoint-security controls
* Driver-specific loading requirements

Therefore, this tool should be treated as a **blocklist comparison/auditing tool**, not as a guarantee that a driver is loadable.

---

# Requirements

## Operating System

Windows with PowerShell support.

## PowerShell

The script is designed for Windows PowerShell 5.1+.

It uses:

```powershell
System.Web.Extensions
```

to deserialize the large LOLDrivers JSON database.

---

# Installation

Clone the repository:

```powershell
git clone <YOUR-REPOSITORY-URL>
cd <YOUR-REPOSITORY-DIRECTORY>
```

Or download the repository ZIP and extract it.

The main script is:

```text
check_allowed_drivers.ps1
```

---

# Usage

Run the script from PowerShell:

```powershell
.\check_allowed_drivers.ps1
```

If your PowerShell configuration prevents locally downloaded scripts from running, use your organization's approved PowerShell/script-signing procedure rather than disabling security controls globally.

You can also inspect the script before execution:

```powershell
Get-Content .\check_allowed_drivers.ps1
```

---

# Example Workflow

A normal run follows four stages.

### 1. Download LOLDrivers

```text
[1/4] Downloading LOLDrivers database...
```

The complete database is downloaded and parsed.

The script then reports:

```text
Total entries   : ...
Vulnerable only : ...
Skipped         : ...
```

---

### 2. Download Microsoft's blocklist

```text
[2/4] Downloading VulnerableDriverBlockList...
```

The ZIP is downloaded to the user's temporary directory.

It is then extracted automatically.

---

### 3. Parse the Code Integrity policy

```text
[3/4] Parsing VulnerableDriverBlockList XML...
```

The script reports policy metadata when available:

```text
VersionEx : ...
PolicyID  : ...
Name      : ...
```

It also reports:

```text
Deny hash rules     : ...
Deny filename rules : ...
```

---

### 4. Compare the databases

```text
[4/4] Comparing LOLDrivers against blocklist...
```

Each vulnerable LOLDriver is compared against the extracted Microsoft deny rules.

---

# Output

The final output is divided into two categories.

## Matched Drivers

```text
Blocked / matched drivers:
----------------------------------------------

  example.sys
      Match : Hash
      Hash  : ...
      Rule  : ...
```

A hash match means a known hash associated with that LOLDrivers entry was found in a Microsoft `Deny` rule.

A filename match is displayed as:

```text
Match : FileName
```

---

## Drivers Not Matched

The script also displays:

```text
Vulnerable drivers NOT in MS blocklist:
----------------------------------------------
  example.sys
  example2.sys
```

These entries represent LOLDrivers vulnerable-driver records for which the script did not find a corresponding Microsoft hash or filename deny rule.

Again, **not matched does not mean guaranteed loadability**.

---

# JSON Output

The script writes a machine-readable report to:

```text
%TEMP%\lol_drivers_policy_results.json
```

The report contains information including:

```json
{
    "Source_LOLDrivers": "...",
    "Source_Blocklist": "...",
    "BlocklistXml": "...",
    "TotalLOLDrivers": 0,
    "VulnerableOnly": 0,
    "Matched": 0,
    "NotMatched": 0,
    "MatchedDrivers": [],
    "NotMatchedDrivers": []
}
```

This makes the results easier to consume from another PowerShell script, Python program, SIEM workflow, or other defensive tooling.

---

# Temporary Files

The script uses the Windows temporary directory.

The following files/directories may be created:

```text
%TEMP%\VulnerableDriverBlockList.zip
%TEMP%\VulnerableDriverBlockList\
%TEMP%\lol_drivers_policy_results.json
```

The extracted blocklist directory is removed before a fresh extraction.

---

# Error Handling

The script uses:

```powershell
$ErrorActionPreference = "Stop"
```

Network and extraction failures are therefore surfaced rather than silently ignored.

For example, failures to download either source produce an explicit error.

The script also verifies that:

```text
DriverPolicy_Enforced.xml
```

was actually found after extraction.

If it cannot be found, the extracted files are printed before the script terminates.

---

# Why This Version Uses Its Own JSON Parser

The LOLDrivers database is large enough that standard PowerShell JSON handling can become problematic depending on the PowerShell/.NET environment and the size of the downloaded document.

This version uses:

```powershell
System.Web.Extensions
```

and:

```powershell
JavaScriptSerializer
```

with:

```powershell
$ser.MaxJsonLength = [Int32]::MaxValue
```

This allows the script to deserialize the large API response without relying on the default JSON size limitation.

---

# Differences From the Original Trail of Bits Project

The original Trail of Bits implementation checks the current HVCI blocklist against LOLDrivers and historically relied on extracting the Code Integrity policy from the system.

This fork changes the workflow substantially:

| Area                           | Original                   | This version                              |
| ------------------------------ | -------------------------- | ----------------------------------------- |
| LOLDrivers                     | Downloaded                 | Downloaded                                |
| LOLDrivers filtering           | Vulnerable + other entries | Vulnerable-driver entries only            |
| Microsoft policy               | Local HVCI policy          | Microsoft Vulnerable Driver Blocklist ZIP |
| Policy extraction              | System-policy workflow     | ZIP extraction                            |
| XML parsing                    | Policy parser workflow     | Native PowerShell XML                     |
| Hash matching                  | Yes                        | Yes                                       |
| Filename matching              | Yes                        | Yes                                       |
| Authentihash handling          | Supported                  | Supported                                 |
| JSON report                    | No                         | Yes                                       |
| Temporary blocklist extraction | N/A                        | Yes                                       |
| Large JSON handling            | Older approach             | `JavaScriptSerializer`                    |

The original project's documented purpose is to identify LOLDrivers that are allowed by the current HVCI blocklist.

---

# Defensive Security Use Cases

This tool can be useful for:

* Security auditing
* HVCI/blocklist visibility
* Windows hardening assessments
* Vulnerable-driver inventory work
* Comparing Microsoft's coverage against LOLDrivers
* Tracking changes to Microsoft's blocklist
* Generating machine-readable audit results
* Researching gaps between public vulnerable-driver databases and Microsoft's deny policy

A useful workflow is to periodically run the script and archive:

```text
lol_drivers_policy_results.json
```

This allows changes in blocklist coverage to be compared over time.

---

# Limitations

This project intentionally performs a **data comparison**, not a complete Windows driver-loading test.

In particular, it does not:

* Install drivers
* Load drivers
* Modify the Windows Code Integrity policy
* Disable HVCI
* Modify Secure Boot
* Modify the Microsoft vulnerable-driver blocklist
* Exploit vulnerable drivers
* Attempt to bypass Windows security controls

A `NotMatched` result should therefore be interpreted as:

> "No corresponding Microsoft deny hash or filename rule was found by this comparison."

It should **not** be interpreted as:

> "This driver is guaranteed to load."

---

# Network Sources

The script retrieves data from:

### LOLDrivers

[LOLDrivers](https://www.loldrivers.io/?utm_source=chatgpt.com)

API:

```text
https://www.loldrivers.io/api/drivers.json
```

### Microsoft Vulnerable Driver Blocklist

The script uses Microsoft's downloadable:

```text
VulnerableDriverBlockList.zip
```

The URL is defined directly in:

```powershell
$blocklistZipUrl
```

---

# Security Considerations

The script downloads external data and parses it locally.

Before using it in an enterprise environment, review:

* Network access requirements
* Proxy configuration
* TLS configuration
* PowerShell execution controls
* Script signing requirements
* EDR/AV policies
* Temporary-directory permissions
* Organizational software-execution policies

For production environments, consider pinning known-good source versions or maintaining an internally reviewed copy of the input datasets.

---

# Attribution

This project is derived from:

**Trail of Bits — HVCI-loldrivers-check**

[Original repository](https://github.com/trailofbits/HVCI-loldrivers-check?utm_source=chatgpt.com)

The original repository credits Trail of Bits and its contributors and is licensed under Apache License 2.0. Check the upstream repository's license and retain the applicable attribution/license notices when redistributing derived work.

This repository contains substantial modifications to the original implementation, including the Microsoft blocklist download/extraction workflow, XML parsing, matching logic, large-JSON handling, and JSON reporting.

---

# License

See the repository's `LICENSE` file.

If this repository is distributed as a derivative of the original project, retain the upstream license and attribution requirements.

---

# Disclaimer

This project is intended for **defensive security research, auditing, and Windows security assessment**.

It does not attempt to defeat Windows security protections or provide a mechanism for bypassing HVCI, Code Integrity, Secure Boot, or Microsoft's vulnerable-driver protections.

Use it only on systems and environments where you have authorization to perform security testing.

---

## Quick Start

```powershell
git clone <YOUR-REPOSITORY-URL>
cd <YOUR-REPOSITORY-DIRECTORY>

.\check_allowed_drivers.ps1
```

Results are displayed in the console and saved to:

```text
%TEMP%\lol_drivers_policy_results.json
```
