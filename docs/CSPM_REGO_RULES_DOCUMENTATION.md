# CSPM Rego Rules Documentation

## Repository Overview

This repository contains a comprehensive collection of **Cloud Security Posture Management (CSPM)** rules written in **Rego** (Open Policy Agent language) for multiple cloud providers and deployment models. The repository serves as a compliance testing framework for cloud infrastructure security.

### Repository Structure

```
prancer-compliance-test/
├── aws/                    # AWS Cloud Security Rules
│   ├── ack/               # AWS Controller for Kubernetes (ACK)
│   ├── cloud/             # AWS Cloud API Resources
│   ├── iac/               # AWS Infrastructure as Code (CloudFormation)
│   └── terraform/         # AWS Terraform Resources
├── azure/                 # Azure Cloud Security Rules
│   ├── aso/               # Azure Service Operator
│   ├── cloud/             # Azure Cloud API Resources
│   ├── iac/               # Azure Infrastructure as Code (ARM Templates)
│   └── terraform/         # Azure Terraform Resources
├── google/                # Google Cloud Security Rules
│   ├── cloud/             # GCP Cloud API Resources
│   ├── iac/               # GCP Infrastructure as Code (Deployment Manager)
│   ├── kcc/               # Kubernetes Config Connector
│   └── terraform/         # GCP Terraform Resources
├── kubernetes/            # Kubernetes Security Rules
│   ├── cloud/             # Kubernetes Cloud Resources
│   └── iac/               # Kubernetes Infrastructure as Code
├── docs/                  # Documentation and Reports
│   ├── help/              # Best practices and guidelines
│   └── sca-report/        # Static Code Analysis Reports
└── utils/                 # Utility Scripts
    ├── aws/               # AWS compliance test generators
    └── google/            # GCP compliance test generators
```

## Cloud Providers Supported

### 1. Amazon Web Services (AWS)
- **Total Rules**: 800+ security policies
- **Categories**: 
  - ACK (AWS Controller for Kubernetes)
  - Cloud API Resources
  - Infrastructure as Code (CloudFormation)
  - Terraform Resources

### 2. Microsoft Azure
- **Total Rules**: 600+ security policies
- **Categories**:
  - ASO (Azure Service Operator)
  - Cloud API Resources
  - Infrastructure as Code (ARM Templates)
  - Terraform Resources

### 3. Google Cloud Platform (GCP)
- **Total Rules**: 400+ security policies
- **Categories**:
  - Cloud API Resources
  - Infrastructure as Code (Deployment Manager)
  - Kubernetes Config Connector (KCC)
  - Terraform Resources

### 4. Kubernetes
- **Total Rules**: 80+ security policies
- **Categories**:
  - Cloud Resources
  - Infrastructure as Code

## Rule Categories by Deployment Model

### Infrastructure as Code (IaC)
Rules that analyze infrastructure templates before deployment:
- **AWS CloudFormation** templates
- **Azure ARM** templates
- **Google Deployment Manager** templates
- **Terraform** configurations
- **Kubernetes** YAML manifests

### Cloud API Resources
Rules that analyze live cloud resources via APIs:
- Real-time resource configuration analysis
- Runtime security posture assessment
- Compliance monitoring of deployed resources

### Container Orchestration
Rules specific to container platforms:
- **AWS ACK** (AWS Controller for Kubernetes)
- **Azure ASO** (Azure Service Operator)
- **Google KCC** (Kubernetes Config Connector)
- **Native Kubernetes** resources

## Rule Naming Convention

All rules follow a standardized naming pattern:
```
PR-<CLOUD>-<TYPE>-<SERVICE>-<ID>
```

Where:
- **PR**: Prancer Rule prefix
- **CLOUD**: AWS, AZR (Azure), GCP, K8S (Kubernetes)
- **TYPE**: CLD (Cloud), CFR (CloudFormation), TRF (Terraform), etc.
- **SERVICE**: Service abbreviation (S3, KV, BKT, etc.)
- **ID**: Unique identifier (001, 002, etc.)

### Examples:
- `PR-AWS-CFR-S3-001`: AWS CloudFormation S3 rule #001
- `PR-AZR-CLD-KV-002`: Azure Cloud Key Vault rule #002
- `PR-GCP-TRF-BKT-001`: GCP Terraform Storage Bucket rule #001
- `PR-K8S-0001`: Kubernetes rule #001

## Rule Structure

Each Rego rule follows a consistent structure based on OPA best practices:

### 1. Package Declaration
```rego
package rule
```

### 2. Default Values
```rego
default <rule_name> = null
```

### 3. Issue Detection
```rego
<cloud>_issue["<rule_name>"] {
    # Conditions that indicate a security issue
}

<cloud>_attribute_absence["<rule_name>"] {
    # Conditions for missing required attributes
}
```

### 4. Rule Evaluation
```rego
<rule_name> {
    # Conditions for rule to pass
    not <cloud>_issue["<rule_name>"]
    not <cloud>_attribute_absence["<rule_name>"]
}

<rule_name> = false {
    <cloud>_issue["<rule_name>"]
}
```

### 5. Error Messages
```rego
<rule_name>_err = "Error message for issues" {
    <cloud>_issue["<rule_name>"]
}

<rule_name>_miss_err = "Error message for missing attributes" {
    <cloud>_attribute_absence["<rule_name>"]
}
```

### 6. Metadata
```rego
<rule_name>_metadata := {
    "Policy Code": "PR-AWS-CFR-S3-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Rule title",
    "Policy Description": "Detailed description",
    "Resource Type": "aws::s3::bucket",
    "Policy Help URL": "Link to documentation",
    "Resource Help URL": "Link to resource documentation"
}
```

### 7. Source Path (Optional)
```rego
source_path[{"<rule_name>": metadata}] {
    # Conditions
    metadata := {
        "resource_path": [["path", "to", "resource"]],
    }
}
```

## Compliance Frameworks Supported

The rules are mapped to various compliance frameworks:

### Security Standards
- **CIS** (Center for Internet Security)
- **NIST** (National Institute of Standards and Technology)
- **ISO 27001**
- **SOC 2**
- **PCI DSS**

### Regulatory Compliance
- **GDPR** (General Data Protection Regulation)
- **HIPAA** (Health Insurance Portability and Accountability Act)
- **CCPA** (California Consumer Privacy Act)
- **LGPD** (Brazilian Data Protection Law)

### Industry Frameworks
- **APRA** (Australian Prudential Regulation Authority)
- **CMMC** (Cybersecurity Maturity Model Certification)
- **HITRUST**
- **CSA CCM** (Cloud Security Alliance Cloud Controls Matrix)

### Threat Intelligence
- **MITRE ATT&CK** Framework mapping

## Master Compliance Test Files

Each cloud provider directory contains master test configuration files:

### Structure
- `master-compliance-test.json`: Test definitions and metadata
- `master-snapshot.json`: Resource snapshot configurations

### Test Case Format
```json
{
    "masterTestId": "PR-AWS-CLD-KMS-001",
    "type": "rego",
    "rule": "file(kms.rego)",
    "masterSnapshotId": ["TEST_KMS"],
    "evals": [{
        "id": "PR-AWS-CLD-KMS-001",
        "eval": "data.rule.kms_key_rotation",
        "message": "data.rule.kms_key_rotation_err",
        "remediationDescription": "Remediation instructions",
        "remediationFunction": "PR_AWS_CLD_KMS_001.py"
    }],
    "severity": "Medium",
    "title": "Rule title",
    "description": "Rule description",
    "tags": [{
        "cloud": "AWS",
        "compliance": ["CIS", "NIST"],
        "service": ["kms"]
    }]
}
```

## Service Coverage

### AWS Services
- **Storage**: S3, EBS, EFS
- **Compute**: EC2, Lambda, ECS, EKS
- **Database**: RDS, DynamoDB, ElastiCache
- **Security**: IAM, KMS, CloudTrail, GuardDuty
- **Networking**: VPC, ELB, CloudFront, API Gateway
- **Management**: CloudWatch, Config, Systems Manager

### Azure Services
- **Storage**: Storage Accounts, Disks
- **Compute**: Virtual Machines, AKS, Container Instances
- **Database**: SQL Database, CosmosDB, PostgreSQL
- **Security**: Key Vault, Security Center, Active Directory
- **Networking**: Virtual Networks, Application Gateway, Front Door
- **Management**: Monitor, Policy, Resource Manager

### Google Cloud Services
- **Storage**: Cloud Storage, Persistent Disks
- **Compute**: Compute Engine, GKE, Cloud Functions
- **Database**: Cloud SQL, Firestore, BigQuery
- **Security**: IAM, KMS, Security Command Center
- **Networking**: VPC, Load Balancing, Cloud CDN
- **Management**: Cloud Monitoring, Cloud Logging

### Kubernetes Resources
- **Workloads**: Pods, Deployments, StatefulSets
- **Services**: Services, Ingress, NetworkPolicies
- **Configuration**: ConfigMaps, Secrets
- **Security**: RBAC, PodSecurityPolicies, ServiceAccounts

## Utility Scripts

### AWS Compliance Generator
- **Location**: `utils/aws/create_master_compliance.py`
- **Purpose**: Automatically generates master compliance test files from Rego rules
- **Features**:
  - Parses Rego files for rule definitions
  - Extracts metadata and creates test cases
  - Maintains compliance framework mappings

### Google Cloud Compliance Generator
- **Location**: `utils/google/create_master_compliance.py`
- **Purpose**: Generates GCP-specific compliance test configurations
- **Features**:
  - Similar functionality to AWS generator
  - Adapted for GCP resource types and naming conventions

## Documentation and Reports

### Best Practices Guide
- **Location**: `docs/help/best_practices.md`
- **Content**: Guidelines for creating custom Rego policies
- **Topics**:
  - Rule naming conventions
  - Code structure patterns
  - Testing methodologies
  - Dependency handling

### Static Code Analysis Reports
- **Location**: `docs/sca-report/`
- **Content**: Automated vulnerability scan results
- **Coverage**:
  - AWS Labs templates analysis
  - Azure QuickStart templates analysis
  - Compliance test results over time

## Integration with Prancer Platform

This repository serves as the compliance database for the **Prancer Cloud Security Platform**:

- **Real-time Scanning**: Rules are executed against live cloud environments
- **CI/CD Integration**: IaC rules validate templates in development pipelines
- **Compliance Reporting**: Results mapped to regulatory frameworks
- **Remediation Guidance**: Each rule includes fix recommendations

## Contributing Guidelines

### Adding New Rules
1. Follow the established naming convention
2. Use the standard rule structure template
3. Include comprehensive metadata
4. Add compliance framework mappings
5. Provide clear error messages and remediation guidance

### Testing Rules
1. Use the OPA Rego Playground for initial validation
2. Test with sample resource configurations
3. Verify both positive and negative test cases
4. Update master compliance test files

### Documentation Updates
1. Update service coverage lists
2. Add new compliance framework mappings
3. Include examples for complex rules
4. Update utility scripts as needed

## Version History and Maintenance

The repository is actively maintained with regular updates:

- **Monthly Updates**: New rules and compliance mappings
- **Quarterly Reviews**: Rule effectiveness and accuracy
- **Annual Audits**: Compliance framework alignment
- **Continuous Integration**: Automated testing and validation

## Support and Resources

### Documentation Links
- [OPA Rego Language Guide](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Prancer Platform Documentation](https://www.prancer.io)
- [Cloud Provider Security Best Practices](#)

### Community Resources
- GitHub Issues for bug reports and feature requests
- Community contributions welcome via pull requests
- Regular updates and maintenance by Prancer team

---

*This documentation provides a comprehensive overview of the CSMP Rego rules repository. For specific implementation details, refer to individual rule files and the best practices guide.*