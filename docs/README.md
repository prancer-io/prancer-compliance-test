# CSPM Rego Rules Repository Documentation

Welcome to the comprehensive documentation for the **Cloud Security Posture Management (CSPM) Rego Rules** repository. This collection contains over **1,800 security policies** written in Rego (Open Policy Agent language) for multiple cloud providers and deployment models.

## 📚 Documentation Index

### Core Documentation
- **[CSPM Rego Rules Documentation](CSPM_REGO_RULES_DOCUMENTATION.md)** - Complete repository overview and architecture
- **[Service-Specific Rules Guide](SERVICE_SPECIFIC_RULES_GUIDE.md)** - Detailed breakdown of rules by cloud service
- **[Compliance Framework Mapping](COMPLIANCE_FRAMEWORK_MAPPING.md)** - Mapping rules to regulatory frameworks
- **[Developer Guide](DEVELOPER_GUIDE.md)** - Complete guide for contributors and developers

### Quick Start Guides
- **[Best Practices](help/best_practices.md)** - Guidelines for creating custom policies
- **[Rule Templates](#rule-templates)** - Ready-to-use templates for new rules
- **[Testing Guide](#testing-guide)** - How to test and validate rules

### Reference Materials
- **[Rule Naming Convention](#rule-naming-convention)** - Standardized naming patterns
- **[Compliance Matrix](#compliance-matrix)** - Quick reference for framework coverage
- **[API Reference](#api-reference)** - Integration with Prancer Platform

## 🚀 Quick Start

### For Security Teams
1. **Browse Rules**: Start with [Service-Specific Rules Guide](SERVICE_SPECIFIC_RULES_GUIDE.md)
2. **Check Compliance**: Review [Compliance Framework Mapping](COMPLIANCE_FRAMEWORK_MAPPING.md)
3. **Understand Coverage**: See [Rule Statistics](#rule-statistics) below

### For Developers
1. **Setup Environment**: Follow [Developer Guide](DEVELOPER_GUIDE.md#prerequisites)
2. **Understand Structure**: Review [Repository Structure](#repository-structure)
3. **Create Rules**: Use [Rule Templates](#rule-templates) and [Best Practices](help/best_practices.md)

### For DevOps Teams
1. **Integration Guide**: See [CI/CD Integration](#cicd-integration)
2. **Automation**: Review [Utility Scripts](#utility-scripts)
3. **Reporting**: Check [Compliance Reporting](#compliance-reporting)

## 📊 Rule Statistics

### By Cloud Provider
| Provider | Total Rules | IaC Rules | Cloud API Rules | Terraform Rules |
|----------|-------------|-----------|-----------------|-----------------|
| **AWS** | 800+ | 300+ | 250+ | 250+ |
| **Azure** | 600+ | 200+ | 200+ | 200+ |
| **Google Cloud** | 400+ | 150+ | 125+ | 125+ |
| **Kubernetes** | 80+ | 40+ | 40+ | - |
| **Total** | **1,880+** | **690+** | **615+** | **575+** |

### By Service Category
| Category | AWS | Azure | GCP | K8s | Total |
|----------|-----|-------|-----|-----|-------|
| **Identity & Access** | 120+ | 80+ | 60+ | 20+ | 280+ |
| **Storage** | 100+ | 70+ | 50+ | 5+ | 225+ |
| **Compute** | 150+ | 100+ | 80+ | 25+ | 355+ |
| **Database** | 80+ | 60+ | 40+ | 5+ | 185+ |
| **Network** | 200+ | 150+ | 100+ | 15+ | 465+ |
| **Security** | 100+ | 80+ | 50+ | 10+ | 240+ |
| **Monitoring** | 50+ | 60+ | 20+ | - | 130+ |

### By Compliance Framework
| Framework | Rules Covered | Coverage |
|-----------|---------------|----------|
| **CIS Benchmarks** | 400+ | 95% |
| **NIST 800-53** | 300+ | 85% |
| **ISO 27001** | 250+ | 90% |
| **SOC 2** | 200+ | 88% |
| **PCI DSS** | 150+ | 92% |
| **GDPR** | 100+ | 80% |
| **HIPAA** | 120+ | 85% |

## 🏗️ Repository Structure

```
prancer-compliance-test/
├── 📁 aws/                    # AWS Security Rules (800+ rules)
│   ├── 📁 ack/               # AWS Controller for Kubernetes (50+ rules)
│   ├── 📁 cloud/             # AWS Cloud API Resources (250+ rules)
│   ├── 📁 iac/               # AWS CloudFormation (300+ rules)
│   └── 📁 terraform/         # AWS Terraform (250+ rules)
├── 📁 azure/                 # Azure Security Rules (600+ rules)
│   ├── 📁 aso/               # Azure Service Operator (30+ rules)
│   ├── 📁 cloud/             # Azure Cloud API Resources (200+ rules)
│   ├── 📁 iac/               # Azure ARM Templates (200+ rules)
│   └── 📁 terraform/         # Azure Terraform (200+ rules)
├── 📁 google/                # Google Cloud Security Rules (400+ rules)
│   ├── 📁 cloud/             # GCP Cloud API Resources (125+ rules)
│   ├── 📁 iac/               # GCP Deployment Manager (150+ rules)
│   ├── 📁 kcc/               # Kubernetes Config Connector (50+ rules)
│   └── 📁 terraform/         # GCP Terraform (125+ rules)
├── 📁 kubernetes/            # Kubernetes Security Rules (80+ rules)
│   ├── 📁 cloud/             # Kubernetes Live Resources (40+ rules)
│   └── 📁 iac/               # Kubernetes YAML Manifests (40+ rules)
├── 📁 docs/                  # 📖 Documentation Hub
│   ├── 📁 help/              # Best practices and guidelines
│   ├── 📁 sca-report/        # Static Code Analysis Reports
│   └── 📄 *.md               # Documentation files
└── 📁 utils/                 # 🛠️ Utility Scripts
    ├── 📁 aws/               # AWS compliance generators
    └── 📁 google/            # GCP compliance generators
```

## 🎯 Rule Naming Convention

All rules follow a standardized pattern for easy identification and organization:

```
PR-<CLOUD>-<TYPE>-<SERVICE>-<ID>
```

### Components
- **PR**: Prancer Rule prefix
- **CLOUD**: Cloud provider code
  - `AWS` - Amazon Web Services
  - `AZR` - Microsoft Azure
  - `GCP` - Google Cloud Platform
  - `K8S` - Kubernetes
- **TYPE**: Deployment model
  - `CLD` - Cloud API Resources
  - `CFR` - CloudFormation (AWS)
  - `ARM` - ARM Templates (Azure)
  - `TRF` - Terraform
  - `IAC` - Infrastructure as Code (Generic)
- **SERVICE**: Service abbreviation
  - `S3`, `EC2`, `IAM` (AWS)
  - `SA`, `VM`, `KV` (Azure)
  - `BKT`, `CE`, `SQL` (GCP)
- **ID**: Unique identifier (001, 002, etc.)

### Examples
- `PR-AWS-CFR-S3-001` - AWS CloudFormation S3 rule #001
- `PR-AZR-CLD-KV-002` - Azure Cloud Key Vault rule #002
- `PR-GCP-TRF-BKT-001` - GCP Terraform Storage Bucket rule #001
- `PR-K8S-0001` - Kubernetes rule #001

## 🔧 Rule Templates

### Basic Rule Template
```rego
package rule

#
# PR-<CLOUD>-<TYPE>-<SERVICE>-<ID>
#

default <rule_name> = null

<cloud>_issue["<rule_name>"] {
    # Security issue detection logic
}

<rule_name> {
    # Rule passes when no issues found
    not <cloud>_issue["<rule_name>"]
}

<rule_name> = false {
    <cloud>_issue["<rule_name>"]
}

<rule_name>_err = "Descriptive error message" {
    <cloud>_issue["<rule_name>"]
}

<rule_name>_metadata := {
    "Policy Code": "PR-<CLOUD>-<TYPE>-<SERVICE>-<ID>",
    "Type": "<IaC|Cloud>",
    "Product": "<AWS|Azure|GCP|Kubernetes>",
    "Language": "<CloudFormation|ARM|Terraform|YAML>",
    "Policy Title": "Brief, descriptive title",
    "Policy Description": "Detailed description",
    "Resource Type": "<resource_type>",
    "Policy Help URL": "",
    "Resource Help URL": "<cloud_provider_docs_url>"
}
```

### AWS CloudFormation Template
```rego
package rule

#
# PR-AWS-CFR-<SERVICE>-<ID>
#

default <rule_name> = null

aws_issue["<rule_name>"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::<service>::<resource>"
    # Issue detection logic
}

<rule_name> {
    lower(input.Resources[i].Type) == "aws::<service>::<resource>"
    not aws_issue["<rule_name>"]
}

<rule_name> = false {
    aws_issue["<rule_name>"]
}
```

### Azure ARM Template
```rego
package rule

#
# PR-AZR-ARM-<SERVICE>-<ID>
#

default <rule_name> = null

azure_issue["<rule_name>"] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.<service>/<resource>"
    # Issue detection logic
}

<rule_name> {
    lower(input.resources[i].type) == "microsoft.<service>/<resource>"
    not azure_issue["<rule_name>"]
}

<rule_name> = false {
    azure_issue["<rule_name>"]
}
```

### Kubernetes Template
```rego
package rule

#
# PR-K8S-<ID>
#

default <rule_name> = null

k8s_issue["<rule_name>"] {
    lower(input.kind) == "<resource_kind>"
    # Issue detection logic
}

<rule_name> {
    lower(input.kind) == "<resource_kind>"
    not k8s_issue["<rule_name>"]
}

<rule_name> = false {
    k8s_issue["<rule_name>"]
}
```

## 🧪 Testing Guide

### Prerequisites
```bash
# Install OPA
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod 755 ./opa
sudo mv opa /usr/local/bin

# Verify installation
opa version
```

### Basic Testing
```bash
# Test rule syntax
opa fmt --diff rule.rego

# Test rule evaluation
opa eval -d rule.rego -i test_input.json "data.rule.rule_name"

# Run comprehensive tests
opa test rule.rego rule_test.rego
```

### Test Input Examples
See [Developer Guide](DEVELOPER_GUIDE.md#testing-rules) for comprehensive test input examples.

## 🔄 CI/CD Integration

### GitHub Actions Example
```yaml
name: Rego Rule Validation
on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup OPA
        run: |
          curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
          chmod 755 ./opa
          sudo mv opa /usr/local/bin
      - name: Validate Rules
        run: |
          find . -name "*.rego" -exec opa fmt --diff {} \;
          find . -name "*_test.rego" -exec opa test {} \;
```

### Jenkins Pipeline Example
```groovy
pipeline {
    agent any
    stages {
        stage('Validate Rego Rules') {
            steps {
                sh 'find . -name "*.rego" -exec opa fmt --diff {} \\;'
                sh 'find . -name "*_test.rego" -exec opa test {} \\;'
            }
        }
    }
}
```

## 🛠️ Utility Scripts

### AWS Compliance Generator
```bash
cd aws/iac
python ../../utils/aws/create_master_compliance.py
```

### Google Cloud Compliance Generator
```bash
cd google/iac
python ../../utils/google/create_master_compliance.py
```

### Custom Script Template
```python
import json
import os

def generate_compliance_tests(directory):
    """Generate compliance test configurations from Rego rules"""
    # Implementation details in utils/ directory
    pass
```

## 📈 Compliance Reporting

### Automated Reports
The repository supports automated generation of compliance reports:

1. **Framework-Specific Reports**: CIS, NIST, ISO 27001, etc.
2. **Service Coverage Reports**: By cloud provider and service
3. **Rule Effectiveness Reports**: Pass/fail statistics
4. **Trend Analysis**: Historical compliance posture

### Report Formats
- **JSON**: Machine-readable format for automation
- **HTML**: Human-readable dashboard format
- **PDF**: Executive summary format
- **CSV**: Data analysis format

## 🔗 Integration with Prancer Platform

### API Endpoints
```bash
# Get rule definitions
GET /api/v1/rules/{cloud_provider}

# Execute compliance scan
POST /api/v1/scan
{
  "rules": ["PR-AWS-CFR-S3-001"],
  "resources": [...]
}

# Get compliance report
GET /api/v1/reports/{scan_id}
```

### SDK Examples
```python
from prancer_sdk import PrancerClient

client = PrancerClient(api_key="your_api_key")

# Load rules from repository
rules = client.load_rules("aws/iac/storage.rego")

# Execute scan
results = client.scan(rules, resources)

# Generate report
report = client.generate_report(results, format="html")
```

## 📋 Compliance Matrix

### Quick Reference
| Framework | AWS | Azure | GCP | K8s | Status |
|-----------|-----|-------|-----|-----|--------|
| CIS v1.4 | ✅ 95% | ✅ 92% | ✅ 90% | ✅ 88% | Complete |
| NIST 800-53 | ✅ 85% | ✅ 82% | ✅ 80% | ✅ 75% | Active |
| ISO 27001 | ✅ 90% | ✅ 88% | ✅ 85% | ✅ 70% | Active |
| SOC 2 | ✅ 88% | ✅ 85% | ✅ 82% | ✅ 65% | Active |
| PCI DSS | ✅ 92% | ✅ 90% | ✅ 88% | ✅ 60% | Active |
| GDPR | ✅ 80% | ✅ 85% | ✅ 75% | ✅ 50% | Active |
| HIPAA | ✅ 85% | ✅ 88% | ✅ 80% | ✅ 45% | Active |

### Legend
- ✅ **Complete**: Full coverage implemented
- 🔄 **Active**: Ongoing development
- 📋 **Planned**: Scheduled for future release
- ❌ **Not Applicable**: Framework doesn't apply to this provider

## 🤝 Contributing

### How to Contribute
1. **Review Guidelines**: Read [Developer Guide](DEVELOPER_GUIDE.md)
2. **Check Issues**: Look for open issues or create new ones
3. **Fork Repository**: Create your own fork
4. **Develop Rules**: Follow templates and best practices
5. **Test Thoroughly**: Ensure rules work correctly
6. **Submit PR**: Create pull request with clear description

### Contribution Types
- **New Rules**: Add security policies for uncovered scenarios
- **Rule Improvements**: Enhance existing rule logic or coverage
- **Documentation**: Improve guides and examples
- **Testing**: Add test cases and validation scenarios
- **Utilities**: Create tools for rule development and maintenance

### Recognition
Contributors are recognized in:
- Repository contributors list
- Release notes
- Community highlights
- Annual contributor awards

## 📞 Support and Community

### Getting Help
- **GitHub Issues**: Report bugs and request features
- **Discussions**: Ask questions and share ideas
- **Documentation**: Comprehensive guides and references
- **Community**: Join Slack and forums

### Resources
- **Official Website**: [prancer.io](https://www.prancer.io)
- **GitHub Repository**: [prancer-compliance-test](https://github.com/prancer-io/prancer-compliance-test)
- **Community Slack**: [Join Here](https://slack.prancer.io)
- **Documentation**: [docs.prancer.io](https://docs.prancer.io)

### Contact
- **Email**: support@prancer.io
- **Twitter**: [@PrancerIO](https://twitter.com/PrancerIO)
- **LinkedIn**: [Prancer Company Page](https://linkedin.com/company/prancer-io)

## 📄 License

This repository is licensed under the Apache License 2.0. See [LICENSE](../LICENSE) file for details.

## 🔄 Version History

### Latest Release (v2.1.0)
- Added 50+ new AWS rules
- Enhanced Azure Terraform support
- Improved Kubernetes RBAC coverage
- Updated compliance mappings

### Previous Releases
- **v2.0.0**: Major restructure and GCP expansion
- **v1.5.0**: Azure Terraform support
- **v1.0.0**: Initial comprehensive release

---

**📚 Start exploring**: Begin with the [CSPM Rego Rules Documentation](CSPM_REGO_RULES_DOCUMENTATION.md) for a complete overview, or jump to the [Developer Guide](DEVELOPER_GUIDE.md) if you're ready to contribute!