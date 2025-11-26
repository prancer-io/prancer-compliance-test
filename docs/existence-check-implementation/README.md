# Rego Policy Existence Check Implementation Guide

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Problem Statement](#problem-statement)
3. [Solution Architecture](#solution-architecture)
4. [Implementation Plan](#implementation-plan)
5. [Testing Strategy](#testing-strategy)
6. [Migration Guide](#migration-guide)
7. [API Reference](#api-reference)

---

## Executive Summary

This document describes the implementation of **resource existence checking** across all Rego compliance policies in the prancer-compliance-test repository. The goal is to eliminate false positives caused by tests running against non-existent resources.

### Key Changes

| Component | Description |
|-----------|-------------|
| `lib/existence.rego` | New shared library with existence check functions |
| `lib/helpers.rego` | Enhanced helper functions |
| Pattern Update | All rules must check resource existence before compliance |
| Test Infrastructure | New test files and automated test runner |

### Impact

- **384 Rego files** require updates
- **2,343 rules** with `default = null` pattern
- **216 rules** with commented-out type checks
- **Estimated reduction**: 40-60% fewer false positives

---

## Problem Statement

### Current Behavior

The existing Rego policies have three critical issues:

#### Issue 1: No Resource Existence Validation

```rego
# CURRENT (Problematic)
default nsg_rule = null

nsg_rule {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["nsg_rule"]
}
```

**Problem**: When NO NSG exists, the rule returns `null`. Compliance engines may interpret this inconsistently (pass, fail, or skip).

#### Issue 2: Commented-Out Type Checks

```rego
# CURRENT (AWS - securitygroup.rego:12)
port_135 = false {
    # lower(input.Type) == "aws::ec2::securitygroup"    <-- DISABLED!
    ingress := input.SecurityGroups[_].IpPermissions[_]
    ...
}
```

**Problem**: Type validation is disabled, allowing tests to run on wrong resource types.

#### Issue 3: Missing Dependency Validation

```rego
# CURRENT (Azure Firewall)
azure_firewall_premium {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/azurefirewalls"
    lower(resource.sku.tier) == "premium"
}
```

**Problem**: Tests firewall configuration but doesn't verify the associated VNet exists.

### False Positive Scenarios

| Scenario | Input | Expected | Actual | Result |
|----------|-------|----------|--------|--------|
| No NSG in subscription | `{"resources":[]}` | Skip/N/A | `null` | Ambiguous |
| Wrong resource type | Storage Account | Skip/N/A | `null` or `true` | False Pass |
| Missing property | NSG without rules | Fail (missing config) | `null` | Ambiguous |
| Deleted dependency | Firewall, no VNet | Fail (orphaned) | Pass | False Pass |

---

## Solution Architecture

### New File Structure

```
prancer-compliance-test/
├── lib/                           # NEW: Shared libraries
│   ├── existence.rego             # Resource existence functions
│   ├── helpers.rego               # Common helper functions
│   └── types.rego                 # Resource type constants
├── tests/                         # NEW: Test infrastructure
│   ├── azure/
│   │   ├── nsg/
│   │   │   ├── input_compliant.json
│   │   │   ├── input_non_compliant.json
│   │   │   ├── input_no_resource.json
│   │   │   └── input_wrong_type.json
│   │   └── ...
│   ├── aws/
│   └── google/
├── scripts/                       # NEW: Test automation
│   ├── run-tests.sh
│   ├── baseline-test.sh
│   └── generate-report.sh
└── docs/
    └── existence-check-implementation/
        ├── README.md              # This file
        ├── MIGRATION.md           # Migration guide
        └── TESTING.md             # Testing guide
```

### Shared Library Design

#### lib/existence.rego

```rego
package lib.existence

# Check if ANY resource of a specific type exists in input.resources
azure_resource_exists(resource_type) {
    resource := input.resources[_]
    lower(resource.type) == lower(resource_type)
}

# Get count of resources by type
azure_resource_count(resource_type) = count {
    count := count([r | r := input.resources[_]; lower(r.type) == lower(resource_type)])
}

# Check if resources array exists and is not empty
has_resources {
    _ = input.resources[_]
}

# AWS-specific: Check if a top-level key exists with data
aws_resource_exists(key) {
    _ = input[key][_]
}

# GCP-specific: Check resource kind
gcp_resource_exists(kind) {
    lower(input.kind) == lower(kind)
}
```

### Updated Rule Pattern

#### Before (Current)

```rego
package rule

default nsg_in_tcp_all_src = null

azure_issue["nsg_in_tcp_all_src"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    rule := resource.properties.securityRules[_]
    rule.properties.access == "Allow"
    rule.properties.direction == "Inbound"
    rule.properties.sourceAddressPrefix == "*"
}

nsg_in_tcp_all_src {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_issue["nsg_in_tcp_all_src"]
}

nsg_in_tcp_all_src = false {
    azure_issue["nsg_in_tcp_all_src"]
}
```

#### After (With Existence Checks)

```rego
package rule

import data.lib.existence

default nsg_in_tcp_all_src = null

# Resource type constant
nsg_type := "microsoft.network/networksecuritygroups"

# Check if NSG resources exist
nsg_in_tcp_all_src_resource_exists {
    existence.azure_resource_exists(nsg_type)
}

# Issue detection (only runs if resource exists)
azure_issue["nsg_in_tcp_all_src"] {
    existence.azure_resource_exists(nsg_type)
    resource := input.resources[_]
    lower(resource.type) == nsg_type
    rule := resource.properties.securityRules[_]
    rule.properties.access == "Allow"
    rule.properties.direction == "Inbound"
    rule.properties.sourceAddressPrefix == "*"
}

# PASS: Resource exists and is compliant
nsg_in_tcp_all_src {
    nsg_in_tcp_all_src_resource_exists
    not azure_issue["nsg_in_tcp_all_src"]
}

# FAIL: Resource exists and is non-compliant
nsg_in_tcp_all_src = false {
    nsg_in_tcp_all_src_resource_exists
    azure_issue["nsg_in_tcp_all_src"]
}

# NOT APPLICABLE: Resource type doesn't exist (remains null by default)
# The default = null handles this case

# Metadata for skip reason
nsg_in_tcp_all_src_skip_reason = "No Network Security Groups found in the evaluated scope" {
    not nsg_in_tcp_all_src_resource_exists
}
```

---

## Implementation Plan

### Phase 1: Foundation (Week 1)

| Task | Description | Files |
|------|-------------|-------|
| 1.1 | Create `lib/existence.rego` | 1 new file |
| 1.2 | Create `lib/helpers.rego` | 1 new file |
| 1.3 | Create test infrastructure | ~50 test files |
| 1.4 | Document baseline behavior | Test report |

### Phase 2: Azure Implementation (Week 2-3)

| Task | Files | Rules |
|------|-------|-------|
| 2.1 | Update `azure/cloud/nsg.rego` | ~30 rules |
| 2.2 | Update `azure/cloud/azure_firewalls.rego` | ~10 rules |
| 2.3 | Update `azure/cloud/aks.rego` | ~25 rules |
| 2.4 | Update remaining Azure files | ~100 rules |

### Phase 3: AWS Implementation (Week 4-5)

| Task | Files | Rules |
|------|-------|-------|
| 3.1 | Update `aws/cloud/securitygroup.rego` | ~35 rules |
| 3.2 | Update `aws/cloud/ec2.rego` | ~20 rules |
| 3.3 | Update remaining AWS files | ~80 rules |

### Phase 4: GCP Implementation (Week 6)

| Task | Files | Rules |
|------|-------|-------|
| 4.1 | Update `google/cloud/compute.rego` | ~50 rules |
| 4.2 | Update remaining GCP files | ~40 rules |

### Phase 5: Validation (Week 7)

| Task | Description |
|------|-------------|
| 5.1 | Run full test suite |
| 5.2 | Generate comparison report |
| 5.3 | Document any edge cases |
| 5.4 | Update all documentation |

---

## Testing Strategy

### Test Categories

1. **Unit Tests**: Individual rule testing with mock JSON
2. **Integration Tests**: Full policy evaluation with Prancer
3. **Regression Tests**: Ensure existing behavior not broken
4. **Edge Case Tests**: Empty inputs, malformed data, etc.

### Test Input Categories

For EACH rule, create these test inputs:

| Test File | Description | Expected Result |
|-----------|-------------|-----------------|
| `input_compliant.json` | Resource exists, properly configured | `true` |
| `input_non_compliant.json` | Resource exists, misconfigured | `false` |
| `input_no_resource.json` | Resource type doesn't exist | `null` |
| `input_wrong_type.json` | Different resource type present | `null` |
| `input_empty.json` | Empty resources array | `null` |
| `input_missing_property.json` | Resource exists, missing required property | `false` |

### Test Execution Commands

```bash
# Run single rule test
opa eval --input tests/azure/nsg/input_compliant.json \
         --data lib/ \
         --data azure/cloud/nsg.rego \
         "data.rule.nsg_in_tcp_all_src"

# Run all tests for a file
opa test lib/ azure/cloud/nsg.rego azure/cloud/nsg_test.rego -v

# Run full test suite
./scripts/run-tests.sh --all

# Generate baseline report (before changes)
./scripts/baseline-test.sh > reports/baseline.json

# Generate comparison report (after changes)
./scripts/run-tests.sh --compare reports/baseline.json
```

---

## Migration Guide

### Step-by-Step Rule Update Process

1. **Add import statement**
   ```rego
   import data.lib.existence
   ```

2. **Define resource type constant**
   ```rego
   resource_type := "microsoft.network/networksecuritygroups"
   ```

3. **Create existence check rule**
   ```rego
   rule_name_resource_exists {
       existence.azure_resource_exists(resource_type)
   }
   ```

4. **Update issue detection to include existence check**
   ```rego
   azure_issue["rule_name"] {
       existence.azure_resource_exists(resource_type)  # ADD THIS
       resource := input.resources[_]
       # ... rest of logic
   }
   ```

5. **Update pass rule**
   ```rego
   rule_name {
       rule_name_resource_exists  # ADD THIS
       not azure_issue["rule_name"]
   }
   ```

6. **Update fail rule**
   ```rego
   rule_name = false {
       rule_name_resource_exists  # ADD THIS
       azure_issue["rule_name"]
   }
   ```

7. **Add skip reason metadata**
   ```rego
   rule_name_skip_reason = "Resource type not found" {
       not rule_name_resource_exists
   }
   ```

### Checklist for Each File

- [ ] Import `data.lib.existence`
- [ ] Define resource type constants
- [ ] Add `_resource_exists` helper for each rule
- [ ] Update all `azure_issue`/`aws_issue`/`gc_issue` rules
- [ ] Update all pass rules
- [ ] Update all fail rules
- [ ] Add skip reason metadata
- [ ] Create/update unit tests
- [ ] Run tests and verify
- [ ] Update documentation

---

## API Reference

### lib/existence.rego Functions

| Function | Description | Returns |
|----------|-------------|---------|
| `azure_resource_exists(type)` | Check if Azure resource type exists | `true`/`undefined` |
| `azure_resource_count(type)` | Count resources of type | `number` |
| `aws_resource_exists(key)` | Check if AWS resource key has data | `true`/`undefined` |
| `gcp_resource_exists(kind)` | Check if GCP resource kind matches | `true`/`undefined` |
| `has_resources` | Check if input.resources is not empty | `true`/`undefined` |

### lib/helpers.rego Functions

| Function | Description | Returns |
|----------|-------------|---------|
| `has_property(obj, prop)` | Check if object has property | `true`/`undefined` |
| `get_property(obj, prop, default)` | Get property with default | `value` |
| `array_contains(arr, elem)` | Check if array contains element | `true`/`false` |
| `lower_equals(a, b)` | Case-insensitive string compare | `true`/`false` |

---

## Success Criteria

| Metric | Target |
|--------|--------|
| False positive reduction | > 40% |
| All tests passing | 100% |
| No regression in existing behavior | 0 regressions |
| Documentation coverage | 100% of updated files |
| Test coverage | 100% of updated rules |

---

## Appendix: Resource Type Reference

### Azure Resource Types

| Resource | Type String |
|----------|-------------|
| NSG | `microsoft.network/networksecuritygroups` |
| Virtual Network | `microsoft.network/virtualnetworks` |
| Azure Firewall | `microsoft.network/azurefirewalls` |
| AKS Cluster | `microsoft.containerservice/managedclusters` |
| Storage Account | `microsoft.storage/storageaccounts` |
| Key Vault | `microsoft.keyvault/vaults` |

### AWS Resource Keys

| Resource | Input Key |
|----------|-----------|
| Security Groups | `SecurityGroups` |
| EC2 Instances | `Instances` |
| S3 Buckets | `Buckets` |
| IAM Users | `Users` |
| RDS Instances | `DBInstances` |

### GCP Resource Kinds

| Resource | Kind |
|----------|------|
| Firewall | `compute#firewall` |
| Instance | `compute#instance` |
| Network | `compute#network` |
| Disk | `compute#disk` |
