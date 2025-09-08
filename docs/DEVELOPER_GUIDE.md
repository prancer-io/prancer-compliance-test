# Developer Guide for CSPM Rego Rules

## Getting Started

This guide provides comprehensive information for developers who want to contribute to the CSPM Rego rules repository, create new rules, or modify existing ones.

## Prerequisites

### Required Tools
- **OPA (Open Policy Agent)**: Latest version for rule testing
- **Git**: For version control and collaboration
- **Python 3.7+**: For utility scripts and automation
- **Text Editor/IDE**: VS Code with Rego extension recommended
- **Cloud CLI Tools**: AWS CLI, Azure CLI, gcloud (for testing)

### Recommended Setup
```bash
# Install OPA
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod 755 ./opa
sudo mv opa /usr/local/bin

# Install VS Code Rego extension
code --install-extension tsandall.opa

# Clone repository
git clone https://github.com/prancer-io/prancer-compliance-test.git
cd prancer-compliance-test
```

## Repository Structure Deep Dive

### Directory Organization
```
prancer-compliance-test/
├── aws/
│   ├── ack/                    # AWS Controller for Kubernetes
│   │   ├── *.rego             # Individual rule files
│   │   ├── master-compliance-test.json
│   │   └── master-snapshot.json
│   ├── cloud/                  # AWS Cloud API resources
│   ├── iac/                    # AWS CloudFormation templates
│   └── terraform/              # AWS Terraform configurations
├── azure/
│   ├── aso/                    # Azure Service Operator
│   ├── cloud/                  # Azure Cloud API resources
│   ├── iac/                    # Azure ARM templates
│   └── terraform/              # Azure Terraform configurations
├── google/
│   ├── cloud/                  # GCP Cloud API resources
│   ├── iac/                    # GCP Deployment Manager
│   ├── kcc/                    # Kubernetes Config Connector
│   └── terraform/              # GCP Terraform configurations
├── kubernetes/
│   ├── cloud/                  # Kubernetes live resources
│   └── iac/                    # Kubernetes YAML manifests
├── docs/                       # Documentation
├── utils/                      # Utility scripts
└── .gitignore
```

### File Naming Conventions

#### Rego Files
- **Service-based**: `<service>.rego` (e.g., `s3.rego`, `iam.rego`)
- **Functional**: `<function>.rego` (e.g., `storage.rego`, `database.rego`)
- **Special cases**: `all.rego` (aggregates all rules), `tags.rego` (tagging rules)

#### Configuration Files
- **Master Test**: `master-compliance-test.json`
- **Master Snapshot**: `master-snapshot.json`
- **Exclusions**: `.gitignore` (service-specific)

## Rule Development Lifecycle

### 1. Planning Phase
Before writing a new rule:

1. **Identify Security Control**: What specific security issue does this address?
2. **Research Compliance**: Which frameworks require this control?
3. **Define Scope**: What resources and configurations are covered?
4. **Check Existing Rules**: Avoid duplication with existing rules
5. **Plan Testing**: How will you validate the rule works correctly?

### 2. Rule Design Patterns

#### Standard Rule Template
```rego
package rule

# Rule metadata and documentation
# https://docs.cloud-provider.com/service/resource

#
# PR-<CLOUD>-<TYPE>-<SERVICE>-<ID>
#

# Default evaluation result
default <rule_name> = null

# Check for missing required attributes
<cloud>_attribute_absence["<rule_name>"] {
    resource := input.Resources[i]  # or input for cloud resources
    lower(resource.Type) == "<resource_type>"
    not resource.Properties.<required_attribute>
}

# Check for security issues in configuration
<cloud>_issue["<rule_name>"] {
    resource := input.Resources[i]
    lower(resource.Type) == "<resource_type>"
    # Specific conditions that indicate a security issue
    resource.Properties.<attribute> == "<insecure_value>"
}

# Rule passes when no issues or missing attributes
<rule_name> {
    lower(input.Resources[i].Type) == "<resource_type>"
    not <cloud>_issue["<rule_name>"]
    not <cloud>_attribute_absence["<rule_name>"]
}

# Rule fails when issues are found
<rule_name> = false {
    <cloud>_issue["<rule_name>"]
}

<rule_name> = false {
    <cloud>_attribute_absence["<rule_name>"]
}

# Error messages for different failure types
<rule_name>_err = "Descriptive error message for security issues" {
    <cloud>_issue["<rule_name>"]
}

<rule_name>_miss_err = "Error message for missing attributes" {
    <cloud>_attribute_absence["<rule_name>"]
}

# Rule metadata
<rule_name>_metadata := {
    "Policy Code": "PR-<CLOUD>-<TYPE>-<SERVICE>-<ID>",
    "Type": "<IaC|Cloud>",
    "Product": "<AWS|Azure|GCP|Kubernetes>",
    "Language": "<CloudFormation|ARM|Terraform|YAML>",
    "Policy Title": "Brief, descriptive title",
    "Policy Description": "Detailed description of what the rule checks and why it's important",
    "Resource Type": "<resource_type>",
    "Policy Help URL": "Link to rule documentation",
    "Resource Help URL": "Link to cloud provider resource documentation"
}

# Optional: Source path for precise error location
source_path[{"<rule_name>": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "<resource_type>"
    <cloud>_issue["<rule_name>"]
    metadata := {
        "resource_path": [["Resources", i, "Properties", "<attribute_path>"]],
    }
}
```

#### Cloud-Specific Patterns

##### AWS CloudFormation/IaC
```rego
# Resource iteration pattern
aws_issue["rule_name"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    # Rule logic here
}

# Common resource types
# aws::s3::bucket, aws::ec2::instance, aws::iam::role, etc.
```

##### AWS Cloud API
```rego
# Direct input pattern (no Resources wrapper)
aws_issue["rule_name"] {
    lower(input.BucketName) != ""
    not input.ServerSideEncryptionConfiguration
}
```

##### Azure ARM/IaC
```rego
# Resource iteration pattern
azure_issue["rule_name"] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    # Rule logic here
}
```

##### Azure Cloud API
```rego
# Direct input pattern
azure_issue["rule_name"] {
    lower(input.kind) == "storageaccount"
    not input.properties.encryption
}
```

##### Google Cloud
```rego
# Cloud API pattern
gc_issue["rule_name"] {
    not input.encryption.defaultKmsKeyName
}

# IaC pattern
gc_issue["rule_name"] {
    resource := input.resources[i]
    lower(resource.type) == "storage.v1.bucket"
    # Rule logic here
}
```

##### Kubernetes
```rego
# Direct input pattern
k8s_issue["rule_name"] {
    lower(input.kind) == "pod"
    input.spec.containers[_].securityContext.runAsRoot == true
}
```

### 3. Advanced Rule Patterns

#### Complex Condition Handling
```rego
# Multiple conditions with AND logic
aws_issue["complex_rule"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    
    # All conditions must be true
    not resource.Properties.PublicAccessBlockConfiguration
    resource.Properties.AccessControl == "PublicRead"
    count(resource.Properties.BucketPolicy.Statement) > 0
}

# Multiple conditions with OR logic
aws_issue["complex_rule"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    
    # Any condition can trigger the issue
    resource.Properties.AccessControl == "PublicRead"
}

aws_issue["complex_rule"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    
    resource.Properties.AccessControl == "PublicReadWrite"
}
```

#### Array and Object Handling
```rego
# Check array elements
aws_issue["array_rule"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    
    # Check if any ingress rule allows all traffic
    rule := resource.Properties.SecurityGroupIngress[_]
    rule.CidrIp == "0.0.0.0/0"
    rule.IpProtocol == "-1"
}

# Count-based conditions
aws_issue["count_rule"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::iam::role"
    
    # Too many policies attached
    count(resource.Properties.ManagedPolicyArns) > 10
}

# String operations
aws_issue["string_rule"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    
    # Check if bucket name contains sensitive information
    contains(lower(resource.Properties.BucketName), "password")
}
```

#### Dependency Checking (Terraform)
```rego
# Check resource dependencies
azure_issue["vm_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine"
    
    # Check if VM has endpoint protection extension
    count([c | r := input.resources[_];
              r.type == "azurerm_virtual_machine_extension";
              contains(r.properties.virtual_machine_id, resource.properties.compiletime_identity);
              lower(r.properties.type) == "iaasantimalware";
              c := 1]) == 0
}
```

### 4. Testing Rules

#### Unit Testing with OPA
```bash
# Test rule syntax
opa fmt --diff <rule_file>.rego

# Test rule evaluation
opa eval -d <rule_file>.rego -i <test_input>.json "data.rule.<rule_name>"

# Test with multiple inputs
opa test <rule_file>.rego <test_file>_test.rego
```

#### Test Input Examples

##### AWS CloudFormation Test Input
```json
{
  "Resources": {
    "TestBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketName": "test-bucket",
        "AccessControl": "Private",
        "LoggingConfiguration": {
          "DestinationBucketName": "log-bucket",
          "LogFilePrefix": "access-logs/"
        }
      }
    }
  }
}
```

##### Azure ARM Test Input
```json
{
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "name": "teststorageaccount",
      "properties": {
        "encryption": {
          "services": {
            "blob": {
              "enabled": true
            }
          }
        }
      }
    }
  ]
}
```

##### Kubernetes Test Input
```json
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "test-pod"
  },
  "spec": {
    "containers": [
      {
        "name": "test-container",
        "image": "nginx",
        "securityContext": {
          "runAsNonRoot": true,
          "readOnlyRootFilesystem": true
        }
      }
    ]
  }
}
```

#### Test File Structure
```rego
package rule

# Test cases for positive scenarios (rule should pass)
test_rule_passes_with_correct_config {
    rule_name with input as {
        "Resources": {
            "TestResource": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "LoggingConfiguration": {
                        "DestinationBucketName": "log-bucket"
                    }
                }
            }
        }
    }
}

# Test cases for negative scenarios (rule should fail)
test_rule_fails_with_incorrect_config {
    not rule_name with input as {
        "Resources": {
            "TestResource": {
                "Type": "AWS::S3::Bucket",
                "Properties": {}
            }
        }
    }
}

# Test error messages
test_error_message_correct {
    rule_name_err == "Expected error message" with input as {
        # Test input that triggers the error
    }
}
```

### 5. Integration with Master Test Files

#### Updating master-compliance-test.json
When adding new rules, update the master test configuration:

```json
{
    "masterTestId": "PR-AWS-CFR-S3-001",
    "type": "rego",
    "rule": "file(storage.rego)",
    "masterSnapshotId": ["TEST_S3"],
    "evals": [
        {
            "id": "PR-AWS-CFR-S3-001",
            "eval": "data.rule.s3_accesslog",
            "message": "data.rule.s3_accesslog_err",
            "remediationDescription": "Enable S3 access logging...",
            "remediationFunction": "PR_AWS_CFR_S3_001.py"
        }
    ],
    "severity": "Medium",
    "title": "AWS Access logging not enabled on S3 buckets",
    "description": "Checks for S3 buckets without access logging...",
    "tags": [
        {
            "cloud": "AWS",
            "compliance": ["CIS", "NIST"],
            "service": ["s3"]
        }
    ]
}
```

#### Using Utility Scripts
```bash
# Generate master compliance test file
cd aws/iac
python ../../utils/aws/create_master_compliance.py

# Review generated file
cat master-compliance-test-new.json
```

## Code Quality Standards

### Rego Best Practices

#### 1. Naming Conventions
- **Rules**: Use descriptive names that indicate what is being checked
- **Variables**: Use clear, meaningful variable names
- **Functions**: Follow verb_noun pattern (e.g., `check_encryption`, `validate_policy`)

#### 2. Code Organization
```rego
# 1. Package declaration
package rule

# 2. Imports (if any)
import data.utils

# 3. Helper functions
has_property(object, property) {
    _ = object[property]
}

# 4. Default values
default rule_name = null

# 5. Issue detection rules
cloud_issue["rule_name"] {
    # Rule logic
}

# 6. Main rule evaluation
rule_name {
    # Pass conditions
}

# 7. Error messages
rule_name_err = "Error message" {
    # Error conditions
}

# 8. Metadata
rule_name_metadata := {
    # Metadata object
}
```

#### 3. Performance Considerations
- **Minimize iterations**: Use efficient patterns for resource checking
- **Avoid deep nesting**: Keep rule logic as flat as possible
- **Use built-in functions**: Leverage OPA's built-in functions for common operations
- **Cache results**: Use intermediate variables for complex calculations

```rego
# Good: Efficient resource iteration
aws_issue["rule_name"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not resource.Properties.Encryption
}

# Avoid: Nested iterations without purpose
aws_issue["rule_name"] {
    some i, j
    resource := input.Resources[i]
    property := resource.Properties[j]  # Unnecessary if you know the property name
}
```

#### 4. Error Handling
```rego
# Handle missing properties gracefully
aws_issue["rule_name"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    
    # Check if property exists before accessing nested values
    has_property(resource.Properties, "Encryption")
    not resource.Properties.Encryption.ServerSideEncryptionConfiguration
}

# Use attribute absence for missing required properties
aws_attribute_absence["rule_name"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::s3::bucket"
    not has_property(resource.Properties, "Encryption")
}
```

### Documentation Standards

#### 1. Rule Documentation
Each rule file should include:
- **Header comment**: Brief description and cloud provider documentation links
- **Rule ID comment**: Clear identification of the rule
- **Inline comments**: Explain complex logic
- **Metadata**: Complete and accurate metadata object

#### 2. Commit Messages
Follow conventional commit format:
```
type(scope): description

feat(aws): add S3 bucket encryption rule PR-AWS-CFR-S3-003
fix(azure): correct Key Vault access policy validation
docs(k8s): update RBAC rule documentation
test(gcp): add test cases for storage bucket rules
```

#### 3. Pull Request Guidelines
- **Title**: Clear, descriptive title indicating the change
- **Description**: Detailed explanation of what was changed and why
- **Testing**: Evidence that the rule has been tested
- **Compliance**: Note which compliance frameworks are affected
- **Breaking Changes**: Highlight any breaking changes

## Debugging and Troubleshooting

### Common Issues

#### 1. Rule Not Triggering
```bash
# Check rule syntax
opa fmt --diff rule.rego

# Test with minimal input
opa eval -d rule.rego -i test.json "data.rule"

# Enable debug output
opa eval --explain=full -d rule.rego -i test.json "data.rule.rule_name"
```

#### 2. Incorrect Resource Type Matching
```rego
# Debug: Print resource types
debug_resource_types {
    resource := input.Resources[i]
    print(resource.Type)
}

# Common issue: Case sensitivity
lower(resource.Type) == "aws::s3::bucket"  # Correct
resource.Type == "AWS::S3::Bucket"         # May not match
```

#### 3. Property Access Errors
```rego
# Safe property access
safe_access {
    resource := input.Resources[i]
    has_property(resource, "Properties")
    has_property(resource.Properties, "TargetProperty")
    resource.Properties.TargetProperty == "expected_value"
}
```

### Debugging Tools

#### 1. OPA REPL
```bash
# Start interactive session
opa run rule.rego

# Query rules interactively
> data.rule.rule_name
> data.rule.aws_issue["rule_name"]
```

#### 2. VS Code Debugging
- Install OPA extension
- Set breakpoints in Rego files
- Use integrated terminal for testing

#### 3. Logging and Tracing
```rego
# Add debug prints
debug_rule {
    resource := input.Resources[i]
    print("Processing resource:", resource.Type)
    lower(resource.Type) == "aws::s3::bucket"
    print("Found S3 bucket:", resource.Properties.BucketName)
}
```

## Contributing Guidelines

### 1. Before Contributing
- Review existing rules to avoid duplication
- Check open issues and pull requests
- Discuss major changes in GitHub issues first
- Ensure you have the necessary cloud provider knowledge

### 2. Development Process
1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-rule-name`
3. **Develop the rule** following the patterns in this guide
4. **Test thoroughly** with various input scenarios
5. **Update documentation** as needed
6. **Submit a pull request** with clear description

### 3. Code Review Process
- All changes require review by maintainers
- Automated tests must pass
- Rule must be tested with real-world scenarios
- Documentation must be updated
- Compliance mappings must be accurate

### 4. Release Process
- Rules are released monthly
- Critical security rules may be released immediately
- Version numbers follow semantic versioning
- Release notes document all changes

## Advanced Topics

### 1. Custom Functions
```rego
# Create reusable functions
is_public_subnet(subnet) {
    subnet.MapPublicIpOnLaunch == true
}

is_encrypted_volume(volume) {
    volume.Encrypted == true
}

# Use in rules
aws_issue["public_instance"] {
    instance := input.Resources[i]
    lower(instance.Type) == "aws::ec2::instance"
    subnet := input.Resources[j]
    lower(subnet.Type) == "aws::ec2::subnet"
    instance.Properties.SubnetId == subnet.Properties.SubnetId
    is_public_subnet(subnet.Properties)
}
```

### 2. Multi-Resource Rules
```rego
# Check relationships between resources
aws_issue["unprotected_database"] {
    db := input.Resources[i]
    lower(db.Type) == "aws::rds::dbinstance"
    
    # Check if database is in private subnet
    subnet := input.Resources[j]
    lower(subnet.Type) == "aws::ec2::subnet"
    db.Properties.DBSubnetGroupName == subnet.Properties.SubnetId
    
    # Subnet should not be public
    subnet.Properties.MapPublicIpOnLaunch == true
}
```

### 3. Policy Analysis
```rego
# Analyze IAM policies for overly broad permissions
aws_issue["overly_permissive_policy"] {
    policy := input.Resources[i]
    lower(policy.Type) == "aws::iam::policy"
    
    statement := policy.Properties.PolicyDocument.Statement[_]
    statement.Effect == "Allow"
    statement.Action[_] == "*"
    statement.Resource == "*"
}
```

### 4. Compliance Automation
```rego
# Tag rules with compliance frameworks
rule_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-001",
    "Compliance": {
        "CIS": ["3.6"],
        "NIST": ["AU-2", "AU-3"],
        "SOC2": ["CC8.1"],
        "PCI": ["10.1"]
    }
}
```

## Resources and References

### Documentation
- [OPA Documentation](https://www.openpolicyagent.org/docs/)
- [Rego Language Reference](https://www.openpolicyagent.org/docs/latest/policy-reference/)
- [AWS CloudFormation Resource Types](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html)
- [Azure ARM Template Reference](https://docs.microsoft.com/en-us/azure/templates/)
- [GCP Deployment Manager Types](https://cloud.google.com/deployment-manager/docs/configuration/supported-resource-types)

### Tools
- [OPA Playground](https://play.openpolicyagent.org/)
- [Rego VS Code Extension](https://marketplace.visualstudio.com/items?itemName=tsandall.opa)
- [Conftest](https://www.conftest.dev/) - Testing framework for configuration files

### Community
- [OPA Slack](https://slack.openpolicyagent.org/)
- [GitHub Discussions](https://github.com/prancer-io/prancer-compliance-test/discussions)
- [Prancer Community](https://www.prancer.io/community)

---

*This developer guide provides comprehensive information for contributing to the CSPM Rego rules repository. For specific questions or support, please reach out through the community channels or create an issue in the repository.*