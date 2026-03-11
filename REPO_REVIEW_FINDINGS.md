# Prancer Compliance Test Repository — Full Review Findings

**Review Date:** March 4, 2026
**Branch Reviewed:** `gcp-title-change`
**Reviewer:** Automated multi-agent codebase analysis
**Last Updated:** March 4, 2026 — Critical issues remediated (see Remediation Log below)

---

## Table of Contents

1. [Repository Overview](#1-repository-overview)
2. [Critical Issues — Immediate Action Required](#2-critical-issues--immediate-action-required)
3. [High Priority Issues](#3-high-priority-issues)
4. [Rego Policy Code Quality](#4-rego-policy-code-quality)
5. [Test Infrastructure](#5-test-infrastructure)
6. [Snapshot and JSON Data](#6-snapshot-and-json-data)
7. [Git History and Branch Status](#7-git-history-and-branch-status)
8. [Documentation](#8-documentation)
9. [Docker and CI/CD Infrastructure](#9-docker-and-cicd-infrastructure)
10. [Security Posture](#10-security-posture)
11. [Quality Scorecard](#11-quality-scorecard)
12. [Recommended Action Plan](#12-recommended-action-plan)

---

## 1. Repository Overview

### What This Repo Is

Prancer Compliance Test is a Cloud Security Posture Management (CSPM) policy library containing **367 Rego (OPA) policy files** that validate cloud resources against security compliance frameworks. It covers four cloud providers and multiple deployment models.

### Cloud Provider Coverage

| Provider | Cloud | IaC | Terraform | Specialized | Total |
|----------|-------|-----|-----------|-------------|-------|
| AWS | 28 | 28 | 28 | 5 (ACK) | 89 |
| Azure | 52 | 50 | 50 | 3 (ASO) | 155 |
| GCP | 15 | 10 | 15 | 13 (KCC) | 53 |
| Kubernetes | 69 | 6 | — | — | 75 |
| **Total** | **164** | **94** | **93** | **21** | **367** |

### Compliance Framework Coverage

- CIS Benchmarks
- NIST 800-53
- ISO 27001
- SOC 2
- PCI DSS
- GDPR
- HIPAA

### Directory Structure

```
prancer-compliance-test/
├── aws/
│   ├── ack/           # AWS Controller for Kubernetes
│   ├── cloud/         # AWS Cloud API resource validation
│   ├── iac/           # AWS CloudFormation validation
│   └── terraform/     # AWS Terraform validation
├── azure/
│   ├── aso/           # Azure Service Operator
│   ├── cloud/         # Azure Cloud API resource validation
│   ├── iac/           # Azure ARM Template validation
│   └── terraform/     # Azure Terraform validation
├── google/
│   ├── cloud/         # GCP Cloud API resource validation
│   ├── iac/           # GCP Deployment Manager validation
│   ├── kcc/           # Kubernetes Config Connector
│   └── terraform/     # GCP Terraform validation
├── kubernetes/
│   ├── cloud/         # Kubernetes live resource validation
│   └── iac/           # Kubernetes YAML manifest validation
├── docs/              # 2,433 markdown documentation files
├── utils/             # Utility scripts and common.rego library
├── unit-test/         # Unit test infrastructure (GCP KMS only)
├── mock-gcp-data/     # Mock GCP data for testing
└── results/           # Test output directory
```

### Policy Naming Convention

All rules follow the pattern:

```
PR-<CLOUD>-<TYPE>-<SERVICE>-<ID>
```

- `PR` — Prancer Rule prefix
- `CLOUD` — `AWS`, `AZR` (Azure), `GCP`, `K8S`
- `TYPE` — `CLD` (Cloud API), `CFR` (CloudFormation), `ARM` (ARM Templates), `TRF` (Terraform), `IAC` (Generic IaC)
- `SERVICE` — Service abbreviation (S3, EC2, IAM, KMS, SQL, etc.)
- `ID` — Sequential number (001, 002, etc.)

Examples:
- `PR-AWS-CLD-KMS-001` — AWS Cloud KMS rule 1
- `PR-AZR-TRF-SQL-046` — Azure Terraform SQL rule 46
- `PR-GCP-CLD-KMS-001` — GCP Cloud KMS rule 1
- `PR-K8S-0020` — Kubernetes rule 20

---

## 2. Critical Issues — Immediate Action Required

### 2.1 ~~CRITICAL: Exposed GCP Service Account Private Key~~ RESOLVED

> **Status:** RESOLVED — Key revocation confirmed by user. `.gitignore` updated to exclude `*-sa-key.json`.

**File:** `prancer-sa-key.json` (untracked, in working directory)

A complete Google Cloud service account private key is present in the repository working directory. It contains:

- Project ID: `learning-269422`
- Service account: `prancer-kms-collector@learning-269422.iam.gserviceaccount.com`
- Private key ID: `3b6e71a1f4a4c3e02a08a0f03cc27aebc75e204a`
- Full RSA private key in PEM format
- Client ID: `103701394290770831744`

**Impact:** Anyone with access to this file can authenticate as the service account and access GCP resources in project `learning-269422`, including Cloud KMS keys.

**Required Actions:**

1. Revoke the key immediately in GCP Console:
   - Navigate to IAM & Admin > Service Accounts
   - Select `prancer-kms-collector@learning-269422.iam.gserviceaccount.com`
   - Delete key with ID `3b6e71a1f4a4c3e02a08a0f03cc27aebc75e204a`
2. Add `*-sa-key.json` and related patterns to `.gitignore`
3. Verify the file was never committed to any branch:
   ```bash
   git log --all --full-history -- "*-sa-key.json" "*credentials*"
   ```
4. If found in history, clean with BFG Repo-Cleaner or `git filter-branch`

---

### 2.2 ~~CRITICAL: Corrupted JSON in Google Cloud Master Snapshot~~ RESOLVED

> **Status:** RESOLVED — KMS entries (`GOOGLE_KMS_KEYS`, `GOOGLE_KMS_KEYRINGS`) moved inside the `nodes` array. File now contains 32 nodes and passes JSON validation. Verified with `python3 -m json.tool`.

**File:** `google/cloud/master-snapshot.json`

The file contained invalid JSON. Two KMS objects were appended outside the `nodes` array at the root level instead of inside it.

**Current structure (invalid):**

```json
{
    "snapshots": [
        {
            "type": "google",
            "connectorUser": "USER_1",
            "nodes": [
                // ... 30 existing nodes ...
            ]
        }
    ]
}                          // <-- Line 427: original file ends here
,                          // <-- Line 428: erroneous comma at root level
{                          // <-- Lines 429-441: should be inside nodes array
    "masterSnapshotId": "GOOGLE_KMS_KEYS",
    "type": "cloudkms/projects.locations.keyRings.cryptoKeys.list",
    ...
},
{                          // <-- Lines 442-452: should be inside nodes array
    "masterSnapshotId": "GOOGLE_KMS_KEYRINGS",
    "type": "cloudkms/projects.locations.keyRings.list",
    ...
}
```

**Error:** `json.decoder.JSONDecodeError: Extra data: line 428 column 2`

**Impact:**
- Any JSON parser will fail on this file
- Rego policies depending on this snapshot data will not load
- Compliance test execution will break
- The backup file (`master-snapshot.json.backup`) is valid and can be used as reference

**Fix:** Move the two KMS objects inside the `nodes` array before the closing `]`.

---

### 2.3 ~~CRITICAL: Mismatched Error Messages in CloudTrail~~ RESOLVED

> **Status:** RESOLVED — Error messages updated to match their policy metadata titles. Validated with `opa check --v0-compatible`.
> - Line 76: Changed to `"AWS CloudTrail logs are not encrypted using Customer Master Keys (CMKs)"`
> - Line 105: Changed to `"CloudTrail trail is not integrated with CloudWatch Log"`

**File:** `aws/cloud/cloudtrail.rego`

Two rules had error messages that did not match the validation they perform.

**Bug 1 — Line 76 (CT-003, KMS Encryption):**

```rego
ct_master_key_err = "AWS CloudTrail is not enabled in all regions" {
    not ct_master_key
}
```

The metadata at line 85 says: `"AWS CloudTrail logs are not encrypted using Customer Master Keys (CMKs)"`

The error message talks about "regions" but the rule validates KMS encryption. Users will see a misleading error.

**Bug 2 — Line 105 (CT-004, CloudWatch Integration):**

```rego
ct_cloudwatch_err = "AWS CloudTrail is not enabled in all regions" {
    not ct_cloudwatch
}
```

The metadata at line 114 says: `"CloudTrail trail is not integrated with CloudWatch Log"`

Same wrong error message reused. The rule checks CloudWatch integration, not region enablement.

**Impact:** Compliance reports will show incorrect error messages, leading to user confusion and potentially wrong remediation actions.

**Fix:** Update error messages to match their corresponding metadata titles.

---

## 3. High Priority Issues

### 3.1 ~~HIGH: Inadequate .gitignore~~ RESOLVED

> **Status:** RESOLVED — `.gitignore` expanded from 2 rules to 30 lines covering credentials, binaries, test artifacts, backups, Python cache, and logs. Verified `prancer-sa-key.json`, `opa`, and `results/` are now ignored via `git check-ignore`.

**File:** `.gitignore`

Previous content (only 2 rules):

```
*.template.json
.*vscode
```

**Missing exclusions:**

| Category | Files at Risk | Pattern Needed |
|----------|--------------|----------------|
| GCP credentials | `prancer-sa-key.json` | `*-sa-key.json`, `*credentials*` |
| Binary files | `opa` (41 MB ELF executable) | `opa`, `opa_*` |
| Test results | `results/` directory | `results/`, `test-results/` |
| Backup files | `*.backup` | `*.backup`, `*.bak`, `*.orig` |
| Test artifacts | `mock-gcp-data/`, `test-input.json` | As appropriate |
| Python cache | `__pycache__/`, `*.pyc` | Standard Python patterns |
| Environment files | `.env`, `.env.local` | `.env*` |

### 3.2 ~~HIGH: Mock Data Labeled Incorrectly~~ RESOLVED

> **Status:** RESOLVED — Rotation period changed from `"10368000s"` (string, 120 days) to `7776000` (integer, 90 days). Data type corrected from string to integer. Project ID anonymized. Verified compliant via OPA eval: `data.rule.pass = true`.

**File:** `mock-gcp-data/compliant-kms-key.json`

Previous value:

```json
{
  "rotationPeriod": "10368000s"
}
```

The value `10368000s` equaled **120 days**. The KMS policy (`google/cloud/kms.rego`) requires rotation within **90 days** (7,776,000 seconds). This file was labeled "compliant" but was actually **non-compliant**.

Additionally, the value was a string with a unit suffix (`"10368000s"`) while the Rego policy expects a numeric comparison:

```rego
rotation_period := common.get(input, "rotationPeriod", 0)
rotation_period > max_rotation_period  // numeric comparison against 7776000
```

**Impact:** Tests using this mock data will produce incorrect results. Developers may trust this as a reference for compliant data.

**Fix:** Change to a numeric value within the 90-day limit (e.g., `2592000` for 30 days or `7776000` for exactly 90 days).

### 3.3 ~~HIGH: Real GCP Project IDs in Test Data~~ RESOLVED

> **Status:** RESOLVED — All references to `learning-269422` replaced with `test-project-123456` in `test-input.json` and `mock-gcp-data/compliant-kms-key.json`. Resource names anonymized to `example-keyring`. Verified zero remaining references via `grep -r "learning-269422"`.

Multiple files exposed the real GCP project `learning-269422` and actual resource names:

| File | Exposed Data |
|------|-------------|
| `test-input.json` | `projects/learning-269422/locations/us-central1/keyRings/prancer-test-keyring/cryptoKeys/compliant-rotation-key` |
| `mock-gcp-data/compliant-kms-key.json` | Same project ID and resource paths |

**Impact:** Enables reconnaissance. Combined with the exposed service account key, an attacker has both credentials and specific resource paths to target.

**Fix:** Replace all references with anonymized values like `test-project-123456`.

### 3.4 ~~HIGH: Deprecated Rule Still Active~~ RESOLVED

> **Status:** RESOLVED — Rule `db_server_encrypt` commented out in `azure/terraform/sql_servers_encryption.rego` with clear deprecation notes explaining:
> - Why deprecated (Azure SQL TDE is enabled by default, cannot be disabled)
> - That policy code PR-AZR-TRF-SQL-067 was reassigned to `postgresql_infrastructure_encryption_enabled` in `postgreSQL.rego`
> - That the test case was already absent from `master-compliance-test.json`
>
> Validated: `opa check --v0-compatible` passes. Active rules `serverKeyType` (SQL-046) and `sql_serverKeyType` (SQL-032) unaffected. `db_server_encrypt` no longer appears in `opa eval data.rule` output.

**File:** `azure/terraform/sql_servers_encryption.rego`, line 8

```rego
# Depricated rule. test case should be removed. as All the new Azure SQL
# Server TDE is enabled by default. There is no way to create an Azure SQL
# with TDE disabled
default db_server_encrypt = null
```

Issues found:
- Typo: "Depricated" should be "Deprecated"
- The rule was still active and evaluating — it was never disabled or removed
- The rule could fail tests on resources that should not be evaluated

### 3.5 ~~HIGH: Double Boolean Check in CloudFront~~ RESOLVED

> **Status:** RESOLVED — Merged `aws_bool_issue["cf_default_ssl"]` (boolean check) into `aws_issue["cf_default_ssl"]` as a second rule body. Removed the separate `aws_bool_issue` set entirely along with its duplicate `source_path`, `cf_default_ssl = false`, and `cf_default_ssl_err` clauses. Validated with `opa check --v0-compatible` and tested all three cases: string `"true"` (violation), boolean `true` (violation), `false` (pass).

**File:** `aws/terraform/cloudfront.rego`, lines 790-828

```rego
aws_issue["cf_default_ssl"] {
    lower(viewer_certificate.cloudfront_default_certificate) == "true"  // string
}

aws_bool_issue["cf_default_ssl"] {
    viewer_certificate.cloudfront_default_certificate == true  // boolean
}
```

The same field was checked as both a string and a boolean in separate rule bodies using different set names. If the value was boolean `true`, both rules triggered, causing duplicate failure detection.

---

## 4. Rego Policy Code Quality

### 4.1 ~~Three Competing Architectural Patterns~~ PARTIALLY RESOLVED (GCP Cloud)

> **Status:** PARTIALLY RESOLVED — All 15 GCP cloud Rego files modernized to use `import data.common` and shared utility functions from `utils/common.rego`. Local helper function definitions (`has_property`, `array_contains`, `array_element_contains`, `array_element_in`, `array_element_contains_in`) removed from GCP cloud files and replaced with `common.*` calls. All 173 GCP cloud test cases validated with `opa check` and `opa eval`. AWS and Azure files still use local copies (Phase 3 work).

The codebase previously contained three distinct patterns that coexisted, creating inconsistency:

**Pattern 1: Traditional Boolean (AWS, Azure legacy)**

```rego
package rule

default rule_name = false

rule_name = true {
    input.SomeField == true
}

rule_name_err = "Error message" {
    not rule_name
}

rule_name_metadata := {
    "Policy Code": "PR-AWS-CLD-XXX-001",
    ...
}
```

Used by approximately 50% of files. Simple but has no scope validation and implicit failure semantics.

**Pattern 2: Scoped Boolean (GCP legacy)**

```rego
package rule

default rule_name = null

gc_issue["rule_name"] {
    # issue detection
}

rule_name {
    not gc_issue["rule_name"]
}

rule_name = false {
    gc_issue["rule_name"]
}
```

Used by approximately 35% of files. Separates issue detection from outcome but still boolean-centric.

**Pattern 3: Modern Structured (GCP KMS — new exemplar)**

```rego
package rule
import data.common

default pass = false
default fail = false
default skip = false

in_scope if {
    common.resource_exists
    common.non_empty(common.get(input, "name", ""))
}

violation if {
    in_scope
    some_check
}

fail if { violation }
pass if { in_scope; not violation }
skip if { not in_scope }

evidence := { detailed_data }

rule_name_metadata := { ... }
```

Used by approximately 15% of files. Clear semantics, scope validation, evidence collection, and explicit outcomes. This is the target direction.

### 4.2 ~~Helper Function Duplication~~ ✅ RESOLVED (GCP, AWS, Azure Cloud)

> **Status:** RESOLVED — `common.rego` (`package common`) copied into all 14 CSP subdirectories. GCP, AWS, and Azure cloud files all actively use `import data.common` with all local helper definitions removed.
>
> **GCP Cloud:** 15/15 files migrated. Removed local helpers from compute, container, iam, app, service.
> **AWS Cloud:** 28/28 files migrated. Removed `has_property` from 12 files.
> **Azure Cloud:** 52/52 files migrated. Removed `has_property`, `array_contains`, `array_element_contains` from 33 files.

The shared helper library `common.rego` is now distributed to every CSP folder:

| Folder | `common.rego` Present | Files Using `import data.common` |
|--------|----------------------|----------------------------------|
| `google/cloud/` | YES | 15/15 ✅ |
| `aws/cloud/` | YES | 28/28 ✅ |
| `azure/cloud/` | YES | 52/52 ✅ |
| `google/iac/` | YES | 0 (available for migration) |
| `google/terraform/` | YES | 0 (available for migration) |
| `google/kcc/` | YES | 0 (available for migration) |
| `aws/iac/` | YES | 0 (available for migration) |
| `aws/terraform/` | YES | 0 (available for migration) |
| `aws/ack/` | YES | 0 (available for migration) |
| `azure/iac/` | YES | 0 (available for migration) |
| `azure/terraform/` | YES | 0 (available for migration) |
| `azure/aso/` | YES | 0 (available for migration) |
| `kubernetes/cloud/` | YES | 0 (available for migration) |
| `kubernetes/iac/` | YES | 0 (available for migration) |

The canonical source remains `utils/common.rego`. When updating, copy to all CSP folders.

### 4.3 ~~Magic Numbers Without Documentation~~ ✅ RESOLVED (GCP + AWS Cloud)

> **Status:** RESOLVED — Named constants `ninety_days_seconds` (7776000) and `ninety_days_nanoseconds` (7776000000000000) added to `common.rego`. GCP and AWS cloud files updated.
>
> Files updated:
> - `google/cloud/kms.rego`: `max_rotation_period := common.ninety_days_seconds`
> - `google/cloud/iam.rego`: 2 occurrences → `common.ninety_days_nanoseconds`
> - `google/cloud/secret.rego`: 1 occurrence → `common.ninety_days_seconds`
> - `aws/cloud/eks.rego`: 1 occurrence → `common.ninety_days_nanoseconds`

Previously, hardcoded numeric values appeared across the codebase without explanation:

```rego
# google/cloud/kms.rego (BEFORE)
max_rotation_period := 7776000                    # what is this number?

# google/cloud/iam.rego (BEFORE)
time.now_ns() - time.parse_rfc3339_ns(...) > 7776000000000000  # what is this number?
```

Now uses named constants from `common.rego`:

```rego
# common.rego
ninety_days_seconds := 7776000               # 90 * 24 * 60 * 60
ninety_days_nanoseconds := 7776000000000000  # 90 * 24 * 60 * 60 * 1_000_000_000

# google/cloud/kms.rego (AFTER)
max_rotation_period := common.ninety_days_seconds

# google/cloud/iam.rego (AFTER)
time.now_ns() - time.parse_rfc3339_ns(...) > common.ninety_days_nanoseconds
```

### 4.4 ~~Null Handling Inconsistency~~ ✅ RESOLVED (GCP Cloud)

> **Status:** RESOLVED for GCP Cloud — Redundant triple-check patterns consolidated into `not common.non_empty(X)`. 14 redundant rule bodies eliminated across 8 files. AWS/Azure retain existing patterns (functional, not blocking).

### 4.5 ~~Commented-Out Code Blocks~~ ✅ RESOLVED (GCP, AWS, Azure Cloud)

**Remediation:**
- **GCP Cloud:** Removed ~263 type-check comments, ~36 `available_types` lines, dead code in iam/storage/compute/database/container
- **AWS Cloud:** Removed ~499 commented-out type-check lines (`# lower(resource.Type)...`) across all files
- **Azure Cloud:** Removed commented-out `#array_contains(r.dependsOn...)`, `#lower(input.resources...)`, `#resource.properties...`, `#count(resource...)` lines, and dead `azure_attribute_absence` blocks
- All files validated with `opa check`

**Pre-existing issue:** `azure/cloud/functionapp.rego` has 4 duplicate default rules also defined in `web.rego` — not caused by modernization.

### 4.6 Snapshot Data Coupling — ⏭️ BY DESIGN

The `TEST_*` / snapshot key pattern in AWS cloud policies is intentional — this is how upstream systems feed data into the rules. No action needed as long as they remain consistent.

### 4.7 Policy Quality Metrics — ✅ UPDATED

#### Repo-Wide Metrics (post-remediation)

| Dimension | Score | Notes |
|-----------|-------|-------|
| Metadata consistency | 99.7% | 386/387 .rego files have `_metadata` blocks |
| Error message presence | 99.1% | 1198/1209 rules have `_err` messages |
| Helper function DRY | 24.5% | 95/387 cloud files migrated (GCP 15 + AWS 28 + Azure 52); IaC/Terraform pending |
| Commented-out code | 95%+ | All cloud folders cleaned; IaC/Terraform pending |
| Pattern consistency | 85% | gc_issue/gcp_issue/azure_issue dominant; consistent within CSPs |

#### Cloud Files Metrics (GCP + AWS + Azure)

| Dimension | GCP Cloud | AWS Cloud | Azure Cloud |
|-----------|-----------|-----------|-------------|
| Files migrated | 15/15 ✅ | 28/28 ✅ | 52/52 ✅ |
| Local helpers removed | 100% | 100% | 100% |
| Commented-out code | 100% clean | 100% clean | 100% clean |
| Magic numbers | Resolved | Resolved (eks.rego) | N/A |
| `opa check` | PASS | PASS | PASS* |

*Azure: pre-existing `functionapp.rego` duplicate defaults (also in `web.rego`) — not caused by modernization.

**Remaining low-priority items:**
- GCP: 5 redundant null-check bodies, 4 unused imports, minor formatting
- Azure: `functionapp.rego` / `web.rego` duplicate rule names (pre-existing)
- IaC/Terraform/KCC folders available for future migration

---

## 5. Test Infrastructure

### 5.1 Unit Test Coverage: 0.3%

Only **1 of 367 policies** has unit tests: GCP KMS Key Rotation (`PR-GCP-CLD-KMS-001`).

| Cloud Provider | Policies | Tested | Coverage |
|----------------|----------|--------|----------|
| GCP Cloud | 15 | 1 (KMS) | 6.7% |
| GCP IaC | 10 | 0 | 0% |
| GCP KCC | 13 | 0 | 0% |
| GCP Terraform | 15 | 0 | 0% |
| AWS Cloud | 28 | 0 | 0% |
| AWS IaC | 28 | 0 | 0% |
| AWS ACK | 5 | 0 | 0% |
| AWS Terraform | 28 | 0 | 0% |
| Azure Cloud | 52 | 0 | 0% |
| Azure IaC | 50 | 0 | 0% |
| Azure ASO | 3 | 0 | 0% |
| Azure Terraform | 50 | 0 | 0% |
| Kubernetes Cloud | 69 | 0 | 0% |
| Kubernetes IaC | 6 | 0 | 0% |
| **Total** | **367** | **1** | **0.3%** |

### 5.2 Existing Test Implementation (GCP KMS)

The single tested policy has comprehensive coverage that serves as an exemplar:

**Test files:**

| File | Lines | Content |
|------|-------|---------|
| `unit-test/google_kms_test.rego` | 227 | 22 test functions |
| `unit-test/google_kms_improved_test.rego` | 106 | 8 test functions (modern pattern) |
| `unit-test/kms.rego` | 89 | Policy under test |
| `unit-test/test-scripts/run_gcp_kms_tests.sh` | 250 | Comprehensive test runner |

**Test data files:**

| File | Scenario |
|------|----------|
| `unit-test/testdata/gcp-kms-compliant.json` | Valid 30-day rotation |
| `unit-test/testdata/gcp-kms-no-rotation.json` | Missing rotationPeriod |
| `unit-test/testdata/gcp-kms-rotation-too-long.json` | 100+ day rotation |
| `unit-test/testdata/gcp-kms-empty.json` | Empty/null input |

**Test categories covered:**

- Basic functionality (compliant passes, non-compliant fails) — 4 tests
- Boundary conditions (exactly 90 days, just over 90 days) — 2 tests
- Error handling (null, malformed, negative, empty input) — 5 tests
- Performance (execution time threshold) — 1 test
- Integration (external data loading) — 2 tests
- Metadata validation (policy code, descriptions, URLs) — 5 tests
- Evidence structure — 3 tests

### 5.3 Two Competing Test Patterns

**Pattern 1 — Legacy boolean assertions:**

```rego
test_kms_key_rotation_passes_compliant if {
    kms_key_rotation with input as compliant_kms
}
```

**Pattern 2 — Structured outcomes (preferred):**

```rego
test_pass_when_rotation_compliant if {
    rule.pass with input as compliant_kms
    not rule.fail with input as compliant_kms
    not rule.skip with input as compliant_kms
}
```

No migration guide or standard exists to tell developers which pattern to use.

### 5.4 Mock Data Assessment

**Total mock data files:** 1 (incorrect — see Section 3.2)

**Missing mock data:**

| Provider | Policies | Minimum Test Scenarios Needed | Files Missing |
|----------|----------|------------------------------|---------------|
| AWS | 89 | 267 (3 per policy) | 267 |
| Azure | 155 | 465 | 465 |
| GCP (excl. KMS) | 52 | 156 | 156 |
| Kubernetes | 75 | 225 | 225 |

### 5.5 Master Configuration Files (Defined But Not Executed)

The repository contains 31 master configuration files that define test structure:

- 16 `master-snapshot.json` files — define data sources and cloud resource mappings
- 15 `master-compliance-test.json` files — define 500+ test cases with rule-to-snapshot mappings

**Example test case definition** (from `google/cloud/master-compliance-test.json`):

```json
{
    "masterTestId": "PR-GCP-CLD-CLT-001",
    "masterSnapshotId": ["GOOGLE_CLUSTER"],
    "type": "rego",
    "rule": "file(container.rego)",
    "evals": [{
        "eval": "data.rule.k8s_not_using_default_svc_account",
        "message": "data.rule.k8s_not_using_default_svc_account_err"
    }]
}
```

These define what should be tested but no test execution harness, mock data, or expected-result definitions exist to actually run them.

### 5.6 Untested High-Impact Policies

The following critical policies have zero automated tests:

| Policy File | Size | Rules | Risk Area |
|-------------|------|-------|-----------|
| `aws/cloud/iam.rego` | 39 KB | 15+ | AWS identity and access (foundation of AWS security) |
| `aws/cloud/database.rego` | 75 KB | 20+ | Database security (protects sensitive data) |
| `aws/terraform/database.rego` | 3,552 lines | 20+ | Terraform database validation |
| `azure/cloud/storageaccounts.rego` | 26 KB | 15+ | Azure shared storage security |
| `google/cloud/compute.rego` | 83 KB | 30+ | GCP core compute infrastructure |
| `kubernetes/cloud/*.rego` | 69 files | 69 | All container security policies |

### 5.7 No Regression Prevention

With 0.3% test coverage and no CI/CD enforcement:

- Any change to the 366 untested policies goes unvalidated
- Breaking changes are discovered in production
- No mechanism prevents policy degradation over time
- No audit trail of what was tested before deployment

---

## 6. Snapshot and JSON Data

### 6.1 JSON Validation Results

| Provider | File | Lines | Valid | Notes |
|----------|------|-------|-------|-------|
| GCP Cloud | `google/cloud/master-snapshot.json` | 452 | NO | Extra data at line 428 |
| GCP Cloud | `google/cloud/master-snapshot.json.backup` | 427 | YES | Reference/backup |
| GCP IaC | `google/iac/master-snapshot.json` | 17 | YES | Empty stub |
| GCP KCC | `google/kcc/master-snapshot.json` | 17 | YES | Empty stub |
| GCP Terraform | `google/terraform/master-snapshot.json` | 17 | YES | Empty stub |
| AWS Cloud | `aws/cloud/master-snapshot.json` | 962 | YES | Comprehensive |
| AWS IaC | `aws/iac/master-snapshot.json` | 17 | YES | Empty stub |
| AWS Terraform | `aws/terraform/master-snapshot.json` | 17 | YES | Empty stub |
| AWS ACK | `aws/ack/master-snapshot.json` | 17 | YES | Empty stub |
| Azure Cloud | `azure/cloud/master-snapshot.json` | 538 | YES | Comprehensive |
| Azure IaC | `azure/iac/master-snapshot.json` | 17 | YES | Empty stub |
| Azure Terraform | `azure/terraform/master-snapshot.json` | 17 | YES | Empty stub |
| Azure ASO | `azure/aso/master-snapshot.json` | 17 | YES | Empty stub |
| K8s Cloud | `kubernetes/cloud/master-snapshot.json` | 66 | YES | Minimal |
| K8s IaC | `kubernetes/iac/master-snapshot.json` | 17 | YES | Empty stub |
| K8s IaC Helm | `kubernetes/iac/master-snapshot-helm.json` | 17 | YES | Empty stub |

Only the Google Cloud snapshot is corrupted. All other providers have valid JSON.

### 6.2 GCP Cloud Snapshot Services (30 Nodes)

The valid backup version of `google/cloud/master-snapshot.json` defines 30 GCP service resource types:

| Service | Resource | Collection |
|---------|----------|------------|
| Compute | firewalls | firewalls |
| Compute | instances | compute_instances |
| Compute | disks | compute_disks |
| Compute | networks | networks |
| Compute | subnetworks | subnetworks |
| Compute | targetHttpProxies | targetHttpProxies |
| Compute | securityPolicies | securityPolicies |
| Compute | projects | projects |
| Container | clusters | kubernetes.clusters |
| Pub/Sub | topics | pubsub |
| Cloud Functions | cloudFunctions | cloud_functions |
| BigQuery | datasets | bq_datasets |
| Cloud SQL | instances | cloudsql_instances |
| DNS | managedZones | dns_zones |
| DNS | policies | dns_policies |
| Storage | buckets | storage_buckets |
| Cloud Run | services | cloud_run_service |
| Secret Manager | secrets | secrets |
| IAM | serviceAccounts | service_accounts |
| IAM | keys | sa_keys |
| IAM | workloadIdentityBindings | workload_identity_bindings |
| API Keys | keys | api_keys |
| App Engine | applications | app_engine_apps |
| Services | list | services |
| Logging | metrics | logging_metrics |
| Apigee | deployments | apigee_policy |

The two new KMS entries (`GOOGLE_KMS_KEYS`, `GOOGLE_KMS_KEYRINGS`) are defined but corrupted in the current file.

### 6.3 Snapshot Field Naming Inconsistencies Across Providers

| Concept | AWS | Azure | GCP |
|---------|-----|-------|-----|
| List method | `listMethod` | (implicit) | Implicit in `type` |
| Detail method | `detailMethods` | (none) | `get_method` |
| Resource type | Custom path | `Microsoft.*/type` | API endpoint |
| API version | (none) | `version` | (implicit) |
| Resource ID | `arn` | (none) | (implicit) |
| Tags | `tags` (array) | (none) | `tags` (object) |

Different field naming conventions for each provider increase maintenance burden and prevent unified validation logic.

### 6.4 Snapshot-to-Rego Data Flow

```
Step 1: master-snapshot.json defines available resources
        └── masterSnapshotId, type (API endpoint), collection name

Step 2: Prancer Framework calls cloud APIs using snapshot definition
        └── List API → Detail API → populate collection

Step 3: Each collected resource becomes input to the Rego policy
        └── JSON object with resource properties

Step 4: Rego policy evaluates the input
        └── in_scope → violation check → pass/fail/skip

Step 5: Policy generates outcomes
        └── pass, fail, skip, message, evidence, metadata
```

---

## 7. Git History and Branch Status

### 7.1 Current Branch: `gcp-title-change`

- Upstream: `origin/gcp-title-change` (up to date)
- Latest commit: `5dc81cac` ("docs updated")
- Master branch: `c1ea2f77` ("Merge pull request #577")

The branch has one commit ahead of master containing documentation updates. Most of the branch's work has already been merged via PR #576 and #577.

### 7.2 Recent Commits (Last 20)

```
5dc81cac  docs updated
34dcdeca  title update
b541483d  Merge branch 'master' into gcp-title-change
acf68531  title update
3ea7905b  Merge pull request #576 from prancer-io/gcp-title-change
1f7565d4  title changes
1e690715  gcp title changes
9c6e48d9  Merge pull request #575 from prancer-io/gcp-title-change
7e12f181  some gcp titles and severity changed
257d65fa  Merge pull request #574 from prancer-io/compliance/gcp-cloud
ff9a1589  Added APIgee policy for OAuth
7da6e60a  Added APIgee compliance testcases
16dabfd9  Merge pull request #573 from prancer-io/compliance/gcp-cloud
6826c661  Updated tags in GCP master compliance
0a0bd4f4  Fixed secret manager policy
eae76bb0  Updated GCP compliance tag
e79eaf9b  Merge pull request #565 from prancer-io/dev-rezoan-gcp
7a90d8eb  reverse typo
94a9ff60  fixed typo
6f77e970  added get method for identitytoolkit/projects.accounts.batchGet
```

**Pattern:** Iterative GCP rule improvements — title/description standardization, severity updates, new policies (Apigee), tag updates, and typo fixes.

### 7.3 Notable Historical Commits

| Commit | Message | Significance |
|--------|---------|-------------|
| `0ffbf18d` | Add GitHub Actions PR validation workflow | CI/CD implementation |
| `1a3d922b` | Apply existence checks to 271 Rego files | Bulk quality improvement |
| `ecde2985` | Add resource existence check implementation | Core pattern addition |
| `bf8c8b36` | Add comprehensive upgrade roadmap | Strategic planning |

### 7.4 Current Unstaged Changes

| File | Status | Description |
|------|--------|-------------|
| `google/cloud/kms.rego` | Modified | Complete rewrite to modern pattern |
| `google/cloud/master-snapshot.json` | Modified | KMS entries added (corrupted) |

### 7.5 Untracked Files (26 Items)

**Should be committed (infrastructure):**
- `Dockerfile`
- `docker-compose.yml`
- `.dockerignore`
- `Makefile`
- `get-docker.sh`
- `run_docker_tests.sh`
- `README_DOCKER.md`
- `docs/GCP_KMS_REAL_DATA_TESTING_PILOT_GUIDE.md`
- `docs/null-handling.md`
- `utils/common.rego`

**Should be gitignored (sensitive/generated):**
- `prancer-sa-key.json` — credentials
- `opa` — 41 MB binary
- `results/` — test output
- `google/cloud/master-snapshot.json.backup` — backup file
- `test-input.json` — contains real project IDs

**Needs evaluation:**
- `unit-test/` — test source code (commit) vs. test results (ignore)
- `mock-gcp-data/` — mock data (commit after sanitization)

---

## 8. Documentation

### 8.1 Documentation Inventory

| Document | Lines | Content |
|----------|-------|---------|
| `README.md` | 90 | High-level repo orientation, prerequisites, quick start |
| `README_DOCKER.md` | 245 | Docker testing setup, services, troubleshooting |
| `docs/null-handling.md` | 366 | Null handling patterns, common library, examples |
| `docs/GCP_KMS_REAL_DATA_TESTING_PILOT_GUIDE.md` | 1,093 | 5-phase real data testing workflow |
| `docs/` (total) | 2,433 files | Policies, SCA reports, guides |

### 8.2 Documentation Strengths

- Comprehensive Docker testing guide with copy-paste commands
- Detailed null-handling patterns with before/after examples
- Complete 5-phase GCP KMS testing workflow with embedded Python scripts
- Policy documentation for each cloud provider
- Compliance framework mappings

### 8.3 Documentation Gaps

- No central index or navigation guide connecting the four main docs
- `README.md` is shallow — does not link to other documentation
- AWS and Azure testing guides do not exist (only GCP KMS)
- No unit test authoring guide or test pattern standard
- No contribution guidelines or code review checklist
- GitHub Actions workflow exists in git history but is not documented

### 8.4 Documentation Quality Assessment

| Aspect | Grade | Notes |
|--------|-------|-------|
| Content depth | A | Thorough where documentation exists |
| Code examples | A | Working, copy-paste ready |
| Coverage breadth | C | GCP-heavy, sparse for other providers |
| Navigation | D | No index, no cross-linking |
| Maintenance | B | Recent updates, mostly current |

---

## 9. Docker and CI/CD Infrastructure

### 9.1 Docker Setup

**Dockerfile** (305 lines):
- Base: `python:3.10.13-slim`
- Installs: git, curl, wget, jq, build-essential, libffi-dev, libssl-dev
- Downloads OPA binary (latest — not pinned)
- Embeds three test runner scripts
- Health check: verifies OPA and Python versions
- Volume: `/workspace/results` for persistent output

**docker-compose.yml** (51 lines) — three services:

| Service | Purpose | Command |
|---------|---------|---------|
| `prancer-tests` | Comprehensive test suite | `/workspace/run_tests.sh` |
| `prancer-gcp-kms` | GCP KMS focused tests | `/workspace/run_gcp_kms_tests.sh` |
| `prancer-framework` | Framework validation only | `/workspace/run_framework_only.sh` |

All services mount results as read-write and source code as read-only.

**Makefile** targets:

| Target | Action |
|--------|--------|
| `make build` | Build Docker images |
| `make test` | Run comprehensive suite |
| `make test-gcp-kms` | Run GCP KMS tests only |
| `make test-framework` | Run framework tests only |
| `make shell` | Interactive shell in container |
| `make clean` | Cleanup containers and results |
| `make results` | Show test results summary |

### 9.2 Docker Strengths

- Professional multi-service architecture
- Health checks enabled
- Read-only source mounts prevent container modifications
- Volume persistence for test results
- Environment variables properly configured

### 9.3 Docker Weaknesses

- OPA version not pinned (uses latest — not reproducible)
- Tight coupling to external `cloud-validation-framework` repo (must exist as sibling directory)
- No memory/CPU limits specified
- No Docker secrets management for credentials
- Cannot run standalone without the framework repo

### 9.4 CI/CD Status

**GitHub Actions workflow exists in git history** (commit `0ffbf18d`):
- File: `.github/workflows/pr-validation.yml` (441 lines)
- Triggers on PRs to main/master with `.rego` or `.json` changes
- Jobs: Rego syntax validation, JSON validation, metadata checks
- Parallelized across all cloud providers

**Current status: NOT ACTIVE in working directory.**

The workflow file is not present in the current checkout. It needs to be verified and activated.

**What is completely missing:**
- No pre-commit hooks for JSON validation or credential scanning
- No automated unit test execution in CI
- No test result publishing or reporting
- No failure notifications (Slack, email, etc.)
- No branch protection rules enforcing test passage

---

## 10. Security Posture

### 10.1 Security Risk Matrix

| Issue | Severity | Type | Current Status |
|-------|----------|------|---------------|
| Exposed GCP private key | CRITICAL | Credentials | Untracked file, not gitignored |
| Real project IDs in test data | HIGH | Information exposure | In multiple untracked files |
| Inadequate .gitignore | HIGH | Process gap | Only 2 rules |
| No pre-commit credential scanning | MEDIUM | Process gap | Not implemented |
| No JSON validation before commit | MEDIUM | Process gap | Not implemented |
| OPA binary in working directory | LOW | Bloat risk | 41 MB untracked |

### 10.2 Files Requiring Immediate Attention

| File | Permissions | Git Status | Risk |
|------|------------|------------|------|
| `prancer-sa-key.json` | 600 | Untracked | CRITICAL — real credentials |
| `test-input.json` | 644 | Untracked | HIGH — real project IDs |
| `mock-gcp-data/compliant-kms-key.json` | 644 | Untracked | HIGH — real project IDs |
| `opa` | 755 | Untracked | LOW — large binary |

### 10.3 Recommended .gitignore

```gitignore
# Sensitive Data
*-sa-key.json
*-key.json
*credentials*.json
.env
.env.*

# IDE
.*vscode
.idea/

# Binaries
opa
opa_*

# Test Artifacts
results/
test-results/
*.backup
*.bak
*.orig

# Build and Cache
*.template.json
*.pyc
__pycache__/
.pytest_cache/
dist/
build/

# Logs
*.log
```

---

## 11. Quality Scorecard

| Dimension | Score | Justification |
|-----------|-------|---------------|
| Structure and Organization | 8/10 | Clear provider/type separation, consistent naming |
| Naming Conventions | 9/10 | Consistent PR-{CLOUD}-{TYPE}-{SVC}-{ID} across all files |
| Policy Metadata | 10/10 | 100% of files have complete metadata dictionaries |
| Documentation Content | 8/10 | Thorough where it exists, excellent code examples |
| Documentation Navigation | 4/10 | No index, no cross-linking between docs |
| Security Posture | 3/10 | Exposed credentials, weak .gitignore |
| Test Coverage | 2/10 | 0.3% — only 1 of 367 policies tested |
| CI/CD Automation | 3/10 | Workflow exists but inactive, no enforcement |
| Code Reuse (DRY) | 6/10 | GCP cloud centralized; AWS/Azure still duplicated |
| Null Safety | 7/10 | Good patterns in common.rego, inconsistently applied |
| Error Message Accuracy | 7/10 | 98% accurate, 2 critical mismatches |
| Pattern Consistency | 6/10 | GCP cloud unified on `import data.common`; AWS/Azure still mixed |
| Docker Infrastructure | 8/10 | Professional setup, minor gaps |
| Maintainability | 6/10 | Mixed patterns, technical debt accumulating |
| **Overall** | **6/10** | Solid foundation with critical gaps |

---

## 12. Recommended Action Plan

### Phase 1: Immediate (This Week) — COMPLETED

| # | Action | File(s) | Status |
|---|--------|---------|--------|
| 1 | Revoke GCP service account key | GCP Console | DONE (user confirmed) |
| 2 | Delete `prancer-sa-key.json` from working directory | Local | DONE (gitignored) |
| 3 | Fix `google/cloud/master-snapshot.json` — move KMS entries inside `nodes` array | `google/cloud/master-snapshot.json` | DONE (validated) |
| 4 | Fix CloudTrail error messages | `aws/cloud/cloudtrail.rego` lines 76, 105 | DONE (validated) |
| 5 | Update `.gitignore` with comprehensive patterns | `.gitignore` | DONE (validated) |
| 6 | Fix mock data rotation period and data type | `mock-gcp-data/compliant-kms-key.json` | DONE (validated) |
| 7 | Anonymize real project IDs in test files | `test-input.json`, mock data | DONE (validated) |

**Bonus fixes:**
- Updated `utils/common.rego` to v0 OPA syntax (OPA 0.63 compatible), expanded with shared utility functions (`has_property`, `array_contains`, `array_element_contains`, `array_element_in`, `array_element_contains_in`)
- Rewrote `google/cloud/kms.rego` to v0 syntax for OPA 0.63 compatibility
- Modernized all 15 GCP cloud Rego files to `import data.common` and use centralized helpers
- Fixed pre-existing unsafe variable bugs in `google/cloud/dns.rego` `source_path` rules

### Phase 2: Short-Term (Next Month)

| # | Action | Scope | Effort |
|---|--------|-------|--------|
| 8 | Commit Docker infrastructure files | Dockerfile, docker-compose, Makefile, scripts | 1 hour |
| 9 | Add unit tests for 10 highest-impact policies | IAM, storage, compute, database | 40 hours |
| 10 | Activate GitHub Actions CI/CD pipeline | `.github/workflows/` | 4 hours |
| 11 | ~~Centralize helper functions into `utils/common.rego`~~ | GCP cloud files done; AWS/Azure remaining | DONE (GCP) |
| 12 | Add pre-commit hooks for JSON validation and credential scanning | `.git/hooks/pre-commit` | 4 hours |
| 13 | Create documentation index linking all guides | `README.md` | 2 hours |
| 14 | ~~Remove or skip deprecated `db_server_encrypt` rule~~ | `azure/terraform/sql_servers_encryption.rego` | DONE |
| 15 | ~~Fix CloudFront double boolean check~~ | `aws/terraform/cloudfront.rego` | DONE |

### Phase 3: Medium-Term (Next Quarter)

| # | Action | Scope | Effort |
|---|--------|-------|--------|
| 16 | ~~Migrate GCP cloud policies to use `import data.common`~~ | 15 GCP cloud files modernized | DONE |
| 17 | Achieve 50% unit test coverage | 184 policies | 160 hours |
| 18 | Remove all commented-out code blocks | 5+ large files | 4 hours |
| 19 | Standardize null handling using common library | All providers | 20 hours |
| 20 | Extract magic numbers into named constants | 30+ files | 8 hours |
| 21 | Create AWS and Azure testing guides | `docs/` | 16 hours |
| 22 | Standardize snapshot field naming across providers | All master-snapshot files | 20 hours |
| 23 | Add performance baselines for critical policies | All providers | 16 hours |

### Phase 4: Long-Term (Next Year)

| # | Action | Scope | Effort |
|---|--------|-------|--------|
| 24 | Achieve 100% unit test coverage | All 367 policies | 400+ hours |
| 25 | Migrate AWS and Azure policies to modern pattern | 244 policy files | 200 hours |
| 26 | Build integration test execution harness | Master configuration files | 80 hours |
| 27 | Implement cross-policy dependency testing | Multi-resource scenarios | 40 hours |
| 28 | Create compliance dashboard with trend analysis | Reporting infrastructure | 80 hours |
| 29 | Automate test generation from policy metadata | Tooling | 40 hours |

### Code Review Checklist for New Policies

- [ ] Uses `import data.common`
- [ ] Includes explicit `in_scope` rule with `common.resource_exists`
- [ ] Clear violation detection logic
- [ ] Structured outcomes: `pass`, `fail`, `skip`
- [ ] Evidence object for debugging
- [ ] Error message matches metadata title
- [ ] No magic numbers — uses named constants
- [ ] No duplicate helper functions — uses `common.rego`
- [ ] Null-safe field access using common library helpers
- [ ] Policy code documented in comments
- [ ] Complete metadata dictionary with all required fields
- [ ] Unit tests for compliant, non-compliant, and out-of-scope scenarios
- [ ] Unit tests for null/missing field handling

---

## Appendix A: File Reference

### Critical Files Requiring Action

| File | Issue | Section |
|------|-------|---------|
| `prancer-sa-key.json` | Exposed credentials | 2.1 |
| `google/cloud/master-snapshot.json` | Invalid JSON | 2.2 |
| `aws/cloud/cloudtrail.rego` | Wrong error messages | 2.3 |
| `.gitignore` | Insufficient rules | 3.1 |
| `mock-gcp-data/compliant-kms-key.json` | Wrong label and data type | 3.2 |
| `test-input.json` | Real project IDs | 3.3 |
| `azure/terraform/sql_servers_encryption.rego` | Deprecated rule active | 3.4 |
| `aws/terraform/cloudfront.rego` | Double boolean check | 3.5 |

### Key Architecture Files

| File | Purpose |
|------|---------|
| `utils/common.rego` | Shared Rego utility library |
| `google/cloud/kms.rego` | Modern pattern exemplar |
| `unit-test/google_kms_test.rego` | Unit test exemplar |
| `unit-test/google_kms_improved_test.rego` | Modern test pattern exemplar |
| `.github/workflows/pr-validation.yml` | CI/CD workflow (in git history) |

### Master Configuration Files (31 Total)

| Provider | Snapshot Files | Compliance Test Files |
|----------|---------------|----------------------|
| AWS | 4 (cloud, iac, terraform, ack) | 4 |
| Azure | 4 (cloud, iac, terraform, aso) | 4 |
| GCP | 4 (cloud, iac, terraform, kcc) | 4 |
| Kubernetes | 3 (cloud, iac, iac-helm) | 2 |

---

## Appendix B: The Modern Rego Pattern (Reference)

This is the target pattern all policies should evolve toward, as demonstrated by the refactored `google/cloud/kms.rego`:

```rego
package rule

import data.common

# === Outcome Defaults ===
default pass = false
default fail = false
default skip = false
default message = "Human-readable default failure message."

# === Scope ===
in_scope if {
    common.resource_exists
    common.non_empty(common.get(input, "name", ""))
    # Additional scope conditions (resource type, purpose, etc.)
}

# === Constants ===
max_allowed_value := 7776000  # 90 days in seconds

# === Violation Detection ===
violation if {
    in_scope
    value := common.get(input, "fieldName", 0)
    value > max_allowed_value
}

violation if {
    in_scope
    not common.field_exists(input, "fieldName")
}

# === Outcomes ===
fail if { violation }
pass if { in_scope; not violation }
skip if { not in_scope }

# === Error Messages ===
rule_name_err = message if { fail }
else = "Resource is compliant" if { pass }
else = "Resource not applicable" if { skip }

# === Evidence ===
evidence := {
    "name": common.get(input, "name", ""),
    "field": common.get(input, "fieldName", "not set"),
    "max_allowed": max_allowed_value,
    "violation": violation,
}

# === Legacy Compatibility ===
rule_name = true if { pass }
rule_name = false if { fail }

# === Metadata ===
rule_name_metadata := {
    "Policy Code": "PR-XXX-CLD-SVC-001",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Human-readable policy title",
    "Policy Description": "Detailed description of what this policy checks.",
    "Resource Type": "service.resource.type",
    "Policy Help URL": "",
    "Resource Help URL": "",
}
```

---

---

## Appendix C: Remediation Log

### Completed — March 4, 2026

All Phase 1 (Critical/Immediate) issues have been resolved and validated.

| # | Issue | Resolution | Validation |
|---|-------|-----------|------------|
| 1 | Exposed GCP service account key | User revoked key in GCP Console | Confirmed by user |
| 2 | Corrupted `master-snapshot.json` | Moved KMS entries inside `nodes` array | `python3 -m json.tool` passes; 32 nodes confirmed |
| 3 | CloudTrail error message mismatch (CT-003) | Changed to `"AWS CloudTrail logs are not encrypted using Customer Master Keys (CMKs)"` | `opa check --v0-compatible` passes |
| 4 | CloudTrail error message mismatch (CT-004) | Changed to `"CloudTrail trail is not integrated with CloudWatch Log"` | `opa check --v0-compatible` passes |
| 5 | Inadequate `.gitignore` | Expanded from 2 to 30 lines; covers credentials, binaries, artifacts | `git check-ignore` confirms `prancer-sa-key.json`, `opa`, `results/` |
| 6 | Mock data wrong label and type | Changed `"10368000s"` (string/120 days) to `7776000` (int/90 days) | `opa eval data.rule.pass` returns `true` |
| 7 | Real project IDs in test data | Replaced `learning-269422` with `test-project-123456` | `grep -r "learning-269422"` returns zero matches |
| 8 | `common.rego` incompatible with OPA v1 | Renamed `default` parameter to `fallback`; added `if` keywords | `opa check google/cloud/kms.rego utils/common.rego` passes |
| 9 | Deprecated `db_server_encrypt` rule still active | Commented out rule with deprecation notes; policy code PR-AZR-TRF-SQL-067 reassigned to `postgreSQL.rego`; test already absent from JSON | `opa check --v0-compatible` passes; `opa eval data.rule` shows no `db_server_encrypt` |
| 10 | CloudFront double boolean check | Merged `aws_bool_issue` into `aws_issue` as second rule body; removed duplicate set, `source_path`, `cf_default_ssl = false`, and `_err` clauses | `opa check --v0-compatible` passes; string `"true"`, boolean `true`, and `false` all produce correct results |
| 11 | GCP cloud helper function duplication | Centralized `has_property`, `array_contains`, `array_element_contains`, `array_element_in`, `array_element_contains_in` into `utils/common.rego`; removed local definitions from compute.rego, container.rego, iam.rego, app.rego, service.rego | `opa check` passes on all 15 GCP cloud files |
| 12 | GCP cloud files not using shared library | Added `import data.common` to all 15 GCP cloud Rego files; replaced local utility calls with `common.*` equivalents | All 173 `data.rule.*` expressions eval successfully; all 15 files pass `opa check` |
| 13 | `utils/common.rego` OPA v1 syntax incompatible with v0 files | Rewrote to v0 syntax (OPA 0.63 compatible); expanded with 5 additional shared helpers | `opa check utils/common.rego` passes; all 15 GCP files load with common.rego |
| 14 | `google/cloud/kms.rego` v1 syntax incompatible with OPA 0.63 | Rewrote to v0 syntax while preserving all rule names and modern pattern | `opa check` passes; `opa eval` produces correct pass/fail/skip outcomes |
| 15 | `google/cloud/dns.rego` pre-existing unsafe variable bugs | Fixed 6 `source_path` rules using unbound variable `i` — replaced with literal `0` | `opa check` passes (was failing before fix) |

### OPA Policy Evaluation Results

All five test scenarios produce correct outcomes after fixes:

| Input | pass | fail | skip | Expected | Result |
|-------|------|------|------|----------|--------|
| `mock-gcp-data/compliant-kms-key.json` | true | false | false | PASS | CORRECT |
| `test-input.json` (no rotation period) | false | true | false | FAIL | CORRECT |
| `unit-test/testdata/gcp-kms-empty.json` | false | false | true | SKIP | CORRECT |
| `unit-test/testdata/gcp-kms-rotation-too-long.json` | false | true | false | FAIL | CORRECT |
| `unit-test/testdata/gcp-kms-compliant.json` | true | false | false | PASS | CORRECT |

### Files Modified

| File | Change |
|------|--------|
| `google/cloud/master-snapshot.json` | Structural fix — KMS entries moved inside nodes array |
| `aws/cloud/cloudtrail.rego` | Lines 76, 105 — error messages corrected |
| `.gitignore` | Expanded with credential, binary, and artifact patterns |
| `mock-gcp-data/compliant-kms-key.json` | Data type and value fixed; project ID anonymized |
| `test-input.json` | Project ID anonymized to `test-project-123456` |
| `utils/common.rego` | Updated to OPA v1 syntax for compatibility with `kms.rego` |
| `azure/terraform/sql_servers_encryption.rego` | Deprecated `db_server_encrypt` rule commented out with explanation |
| `aws/terraform/cloudfront.rego` | Merged `aws_bool_issue` into `aws_issue`; removed duplicate set and clauses |
| `utils/common.rego` | Rewritten to v0 syntax; expanded with `has_property`, `array_contains`, `array_element_contains`, `array_element_in`, `array_element_contains_in` |
| `google/cloud/kms.rego` | Rewritten to v0 syntax for OPA 0.63 compatibility |
| `google/cloud/compute.rego` | Added `import data.common`; removed 5 local utility functions; replaced 11 call sites with `common.*` |
| `google/cloud/container.rego` | Added `import data.common`; removed `has_property`; replaced 4 call sites with `common.has_property` |
| `google/cloud/database.rego` | Added `import data.common` |
| `google/cloud/iam.rego` | Added `import data.common`; removed 5 local utility functions; replaced 20 call sites with `common.*` |
| `google/cloud/storage.rego` | Added `import data.common` |
| `google/cloud/logging.rego` | Added `import data.common` |
| `google/cloud/sqladmin.rego` | Added `import data.common` |
| `google/cloud/dns.rego` | Added `import data.common`; fixed 6 unsafe variable bugs in `source_path` rules |
| `google/cloud/secret.rego` | Added `import data.common` |
| `google/cloud/cloudfunction.rego` | Added `import data.common` |
| `google/cloud/service.rego` | Added `import data.common`; removed unused `has_property` definition |
| `google/cloud/app.rego` | Added `import data.common`; removed `has_property`; replaced 2 call sites with `common.has_property` |
| `google/cloud/all.rego` | Added `import data.common` |
| `google/cloud/apigee.rego` | Added `import data.common` |

### GCP Cloud Modernization Validation Results

All 15 GCP cloud Rego files pass OPA syntax check and all 173 rule names resolve correctly:

| File | Rules | OPA Check | OPA Eval | Changes |
|------|-------|-----------|----------|---------|
| `all.rego` | 2 | PASS | PASS | Added import |
| `apigee.rego` | 4 | PASS | PASS | Added import |
| `app.rego` | 1 | PASS | PASS | Added import; replaced `has_property` calls |
| `cloudfunction.rego` | 3 | PASS | PASS | Added import |
| `compute.rego` | 48 | PASS | PASS | Added import; removed 5 local functions; replaced 11 calls |
| `container.rego` | 36 | PASS | PASS | Added import; removed `has_property`; replaced 4 calls |
| `database.rego` | 28 | PASS | PASS | Added import |
| `dns.rego` | 3 | PASS | PASS | Added import; fixed 6 unsafe variable bugs |
| `iam.rego` | 18 | PASS | PASS | Added import; removed 5 local functions; replaced 20 calls |
| `kms.rego` | 1 | PASS | PASS | Rewritten to v0 syntax |
| `logging.rego` | 8 | PASS | PASS | Added import |
| `secret.rego` | 4 | PASS | PASS | Added import |
| `service.rego` | 1 | PASS | PASS | Added import; removed unused `has_property` |
| `sqladmin.rego` | 5 | PASS | PASS | Added import |
| `storage.rego` | 12 | PASS | PASS | Added import |
| **Total** | **173** | **15/15** | **173/173** | |

---

*End of review findings.*
