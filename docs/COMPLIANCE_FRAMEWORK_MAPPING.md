# Compliance Framework Mapping Guide

## Overview

This document provides a comprehensive mapping of CSPM Rego rules to various compliance frameworks, regulatory standards, and security benchmarks. Use this guide to quickly identify which rules apply to specific compliance requirements.

## Quick Reference Table

| Framework | Total Rules | AWS | Azure | GCP | Kubernetes |
|-----------|-------------|-----|-------|-----|------------|
| CIS Benchmarks | 400+ | 150+ | 120+ | 80+ | 50+ |
| NIST 800-53 | 300+ | 120+ | 90+ | 60+ | 30+ |
| ISO 27001 | 250+ | 100+ | 80+ | 50+ | 20+ |
| SOC 2 | 200+ | 80+ | 60+ | 40+ | 20+ |
| PCI DSS | 150+ | 60+ | 45+ | 30+ | 15+ |
| GDPR | 100+ | 40+ | 35+ | 20+ | 5+ |
| HIPAA | 120+ | 50+ | 40+ | 25+ | 5+ |

## CIS Benchmarks Mapping

### AWS CIS Benchmark v1.4.0

#### Identity and Access Management
| Rule ID | CIS Control | Description | Severity |
|---------|-------------|-------------|----------|
| PR-AWS-CLD-IAM-001 | 1.1 | Maintain current contact details | Low |
| PR-AWS-CLD-IAM-002 | 1.2 | Ensure security contact information is provided | Low |
| PR-AWS-CLD-IAM-003 | 1.3 | Ensure security questions are registered | Low |
| PR-AWS-CLD-IAM-004 | 1.4 | Ensure no root access key exists | Critical |
| PR-AWS-CLD-IAM-005 | 1.5 | Ensure MFA is enabled for root account | Critical |
| PR-AWS-CLD-IAM-006 | 1.6 | Ensure hardware MFA is enabled for root account | High |
| PR-AWS-CLD-IAM-007 | 1.7 | Eliminate use of root access key | Critical |
| PR-AWS-CLD-IAM-008 | 1.8 | Ensure IAM password policy requires minimum length | Medium |
| PR-AWS-CLD-IAM-009 | 1.9 | Ensure IAM password policy prevents password reuse | Medium |
| PR-AWS-CLD-IAM-010 | 1.10 | Ensure multi-factor authentication is enabled | High |

#### Logging
| Rule ID | CIS Control | Description | Severity |
|---------|-------------|-------------|----------|
| PR-AWS-CLD-CT-001 | 3.1 | Ensure CloudTrail is enabled in all regions | High |
| PR-AWS-CLD-CT-002 | 3.2 | Ensure CloudTrail log file validation is enabled | Medium |
| PR-AWS-CLD-CT-003 | 3.3 | Ensure CloudTrail logs are encrypted at rest | High |
| PR-AWS-CLD-CT-004 | 3.4 | Ensure CloudTrail logs are integrated with CloudWatch | Medium |
| PR-AWS-CLD-CT-005 | 3.5 | Ensure AWS Config is enabled | High |
| PR-AWS-CLD-CT-006 | 3.6 | Ensure S3 bucket access logging is enabled | Medium |
| PR-AWS-CLD-CT-007 | 3.7 | Ensure CloudTrail logs S3 bucket is not publicly accessible | Critical |

#### Monitoring
| Rule ID | CIS Control | Description | Severity |
|---------|-------------|-------------|----------|
| PR-AWS-CLD-MON-001 | 4.1 | Ensure log metric filter for unauthorized API calls | Medium |
| PR-AWS-CLD-MON-002 | 4.2 | Ensure log metric filter for Management Console sign-in without MFA | Medium |
| PR-AWS-CLD-MON-003 | 4.3 | Ensure log metric filter for usage of root account | High |
| PR-AWS-CLD-MON-004 | 4.4 | Ensure log metric filter for IAM policy changes | Medium |

### Azure CIS Benchmark v1.4.0

#### Identity and Access Management
| Rule ID | CIS Control | Description | Severity |
|---------|-------------|-------------|----------|
| PR-AZR-CLD-IAM-001 | 1.1 | Ensure security defaults is enabled on Azure Active Directory | High |
| PR-AZR-CLD-IAM-002 | 1.2 | Ensure multi-factor authentication is enabled for all privileged users | Critical |
| PR-AZR-CLD-IAM-003 | 1.3 | Ensure guest users are reviewed on a monthly basis | Medium |
| PR-AZR-CLD-IAM-004 | 1.4 | Ensure that 'Users can register applications' is set to 'No' | Medium |

#### Security Center
| Rule ID | CIS Control | Description | Severity |
|---------|-------------|-------------|----------|
| PR-AZR-CLD-SC-001 | 2.1 | Ensure that standard pricing tier is selected | High |
| PR-AZR-CLD-SC-002 | 2.2 | Ensure that 'Automatic provisioning of monitoring agent' is set to 'On' | Medium |
| PR-AZR-CLD-SC-003 | 2.3 | Ensure ASC Default policy setting is not disabled | Medium |

### GCP CIS Benchmark v1.3.0

#### Identity and Access Management
| Rule ID | CIS Control | Description | Severity |
|---------|-------------|-------------|----------|
| PR-GCP-CLD-IAM-001 | 1.1 | Ensure that corporate login credentials are used | High |
| PR-GCP-CLD-IAM-002 | 1.2 | Ensure that multi-factor authentication is enabled | Critical |
| PR-GCP-CLD-IAM-003 | 1.3 | Ensure that Security Key Enforcement is enabled | High |
| PR-GCP-CLD-IAM-004 | 1.4 | Ensure that users are not assigned the Service Account User role | Medium |

#### Logging and Monitoring
| Rule ID | CIS Control | Description | Severity |
|---------|-------------|-------------|----------|
| PR-GCP-CLD-LOG-001 | 2.1 | Ensure that Cloud Audit Logging is configured properly | High |
| PR-GCP-CLD-LOG-002 | 2.2 | Ensure that sinks are configured for all log entries | Medium |
| PR-GCP-CLD-LOG-003 | 2.3 | Ensure that retention policies on log buckets are configured | Medium |

### Kubernetes CIS Benchmark v1.6.0

#### Control Plane Security Configuration
| Rule ID | CIS Control | Description | Severity |
|---------|-------------|-------------|----------|
| PR-K8S-0001 | 5.1.1 | Minimize access to secrets | High |
| PR-K8S-0002 | 5.1.2 | Minimize wildcard use in Roles and ClusterRoles | Medium |
| PR-K8S-0003 | 5.1.3 | Minimize access to create pods | High |
| PR-K8S-0004 | 5.1.4 | Minimize access to create persistent volumes | Medium |

#### Pod Security Standards
| Rule ID | CIS Control | Description | Severity |
|---------|-------------|-------------|----------|
| PR-K8S-0008 | 5.2.1 | Minimize the admission of privileged containers | High |
| PR-K8S-0009 | 5.2.2 | Minimize the admission of containers wishing to share the host process ID namespace | High |
| PR-K8S-0010 | 5.2.3 | Minimize the admission of containers wishing to share the host IPC namespace | High |
| PR-K8S-0011 | 5.2.4 | Minimize the admission of containers wishing to share the host network namespace | High |

## NIST Framework Mapping

### NIST 800-53 Rev 5

#### Access Control (AC)
| Control | Rule Examples | Description |
|---------|---------------|-------------|
| AC-2 | PR-AWS-CLD-IAM-*, PR-AZR-CLD-IAM-* | Account Management |
| AC-3 | PR-K8S-0001, PR-K8S-0002 | Access Enforcement |
| AC-6 | PR-AWS-CLD-IAM-007, PR-GCP-CLD-IAM-004 | Least Privilege |
| AC-17 | PR-AWS-CLD-VPC-*, PR-AZR-CLD-NSG-* | Remote Access |

#### Audit and Accountability (AU)
| Control | Rule Examples | Description |
|---------|---------------|-------------|
| AU-2 | PR-AWS-CLD-CT-001, PR-AZR-CLD-LOG-* | Event Logging |
| AU-3 | PR-AWS-CLD-CT-002, PR-GCP-CLD-LOG-001 | Content of Audit Records |
| AU-6 | PR-AWS-CLD-MON-*, PR-AZR-CLD-MON-* | Audit Review, Analysis, and Reporting |
| AU-9 | PR-AWS-CLD-CT-003, PR-GCP-CLD-LOG-002 | Protection of Audit Information |

#### System and Communications Protection (SC)
| Control | Rule Examples | Description |
|---------|---------------|-------------|
| SC-8 | PR-AWS-CLD-ELB-*, PR-AZR-CLD-AG-* | Transmission Confidentiality and Integrity |
| SC-13 | PR-AWS-CLD-KMS-*, PR-AZR-CLD-KV-* | Cryptographic Protection |
| SC-28 | PR-AWS-CLD-S3-*, PR-GCP-CLD-BKT-* | Protection of Information at Rest |

### NIST Cybersecurity Framework

#### Identify (ID)
| Function | Rule Examples | Description |
|----------|---------------|-------------|
| ID.AM | PR-AWS-CLD-TAG-*, PR-AZR-CLD-TAG-* | Asset Management |
| ID.GV | PR-AWS-CLD-IAM-*, PR-K8S-RBAC-* | Governance |
| ID.RA | PR-AWS-CLD-SEC-*, PR-AZR-CLD-SEC-* | Risk Assessment |

#### Protect (PR)
| Function | Rule Examples | Description |
|----------|---------------|-------------|
| PR.AC | PR-AWS-CLD-IAM-*, PR-K8S-0001 | Identity Management and Access Control |
| PR.DS | PR-AWS-CLD-S3-*, PR-AZR-CLD-SA-* | Data Security |
| PR.IP | PR-AWS-CLD-VPC-*, PR-AZR-CLD-NSG-* | Information Protection Processes |
| PR.PT | PR-AWS-CLD-WAF-*, PR-AZR-CLD-FW-* | Protective Technology |

#### Detect (DE)
| Function | Rule Examples | Description |
|----------|---------------|-------------|
| DE.AE | PR-AWS-CLD-CT-*, PR-AZR-CLD-LOG-* | Anomalies and Events |
| DE.CM | PR-AWS-CLD-MON-*, PR-GCP-CLD-MON-* | Security Continuous Monitoring |

## ISO 27001:2013 Mapping

### Information Security Policies (A.5)
| Control | Rule Examples | Description |
|---------|---------------|-------------|
| A.5.1.1 | PR-AWS-CLD-IAM-*, PR-AZR-CLD-IAM-* | Information security policies |
| A.5.1.2 | PR-AWS-CLD-GOV-*, PR-AZR-CLD-GOV-* | Review of information security policies |

### Organization of Information Security (A.6)
| Control | Rule Examples | Description |
|---------|---------------|-------------|
| A.6.1.1 | PR-AWS-CLD-ORG-*, PR-AZR-CLD-ORG-* | Information security roles and responsibilities |
| A.6.2.1 | PR-AWS-CLD-MOB-*, PR-AZR-CLD-MOB-* | Mobile device policy |

### Access Control (A.9)
| Control | Rule Examples | Description |
|---------|---------------|-------------|
| A.9.1.1 | PR-AWS-CLD-IAM-*, PR-K8S-0001 | Access control policy |
| A.9.2.1 | PR-AWS-CLD-IAM-005, PR-AZR-CLD-IAM-002 | User registration and de-registration |
| A.9.4.1 | PR-AWS-CLD-IAM-008, PR-AZR-CLD-IAM-003 | Information access restriction |

### Cryptography (A.10)
| Control | Rule Examples | Description |
|---------|---------------|-------------|
| A.10.1.1 | PR-AWS-CLD-KMS-*, PR-AZR-CLD-KV-* | Policy on the use of cryptographic controls |
| A.10.1.2 | PR-AWS-CLD-S3-003, PR-GCP-CLD-BKT-001 | Key management |

## SOC 2 Mapping

### Security
| Criteria | Rule Examples | Description |
|----------|---------------|-------------|
| CC6.1 | PR-AWS-CLD-IAM-*, PR-AZR-CLD-IAM-* | Logical and physical access controls |
| CC6.2 | PR-AWS-CLD-KMS-*, PR-AZR-CLD-KV-* | Encryption of data |
| CC6.3 | PR-AWS-CLD-NET-*, PR-AZR-CLD-NET-* | Network security |

### Availability
| Criteria | Rule Examples | Description |
|----------|---------------|-------------|
| CC7.1 | PR-AWS-CLD-ELB-*, PR-AZR-CLD-LB-* | System availability |
| CC7.2 | PR-AWS-CLD-BAK-*, PR-AZR-CLD-BAK-* | System backup and recovery |

### Processing Integrity
| Criteria | Rule Examples | Description |
|----------|---------------|-------------|
| CC8.1 | PR-AWS-CLD-CT-*, PR-AZR-CLD-LOG-* | Data processing integrity |

### Confidentiality
| Criteria | Rule Examples | Description |
|----------|---------------|-------------|
| CC9.1 | PR-AWS-CLD-S3-*, PR-AZR-CLD-SA-* | Confidential information |

### Privacy
| Criteria | Rule Examples | Description |
|----------|---------------|-------------|
| CC10.1 | PR-AWS-CLD-PII-*, PR-AZR-CLD-PII-* | Personal information collection |

## PCI DSS v3.2.1 Mapping

### Build and Maintain a Secure Network
| Requirement | Rule Examples | Description |
|-------------|---------------|-------------|
| 1.1 | PR-AWS-CLD-VPC-*, PR-AZR-CLD-NSG-* | Firewall configuration standards |
| 1.2 | PR-AWS-CLD-SG-*, PR-AZR-CLD-NSG-* | Firewall and router configurations |
| 2.1 | PR-AWS-CLD-EC2-*, PR-AZR-CLD-VM-* | Default passwords and security parameters |
| 2.2 | PR-AWS-CLD-CFG-*, PR-AZR-CLD-CFG-* | System configuration standards |

### Protect Cardholder Data
| Requirement | Rule Examples | Description |
|-------------|---------------|-------------|
| 3.4 | PR-AWS-CLD-S3-*, PR-AZR-CLD-SA-* | Encryption of cardholder data |
| 3.5 | PR-AWS-CLD-KMS-*, PR-AZR-CLD-KV-* | Key management procedures |
| 4.1 | PR-AWS-CLD-ELB-*, PR-AZR-CLD-AG-* | Encryption of cardholder data transmission |

### Maintain a Vulnerability Management Program
| Requirement | Rule Examples | Description |
|-------------|---------------|-------------|
| 6.1 | PR-AWS-CLD-PAT-*, PR-AZR-CLD-PAT-* | Security patch management |
| 6.2 | PR-AWS-CLD-VUL-*, PR-AZR-CLD-VUL-* | Vulnerability management |

## GDPR Mapping

### Lawfulness, Fairness and Transparency (Article 5)
| Principle | Rule Examples | Description |
|-----------|---------------|-------------|
| 5.1.a | PR-AWS-CLD-PII-*, PR-AZR-CLD-PII-* | Lawful basis for processing |
| 5.1.f | PR-AWS-CLD-SEC-*, PR-AZR-CLD-SEC-* | Security of processing |

### Data Protection by Design and by Default (Article 25)
| Requirement | Rule Examples | Description |
|-------------|---------------|-------------|
| 25.1 | PR-AWS-CLD-ENC-*, PR-AZR-CLD-ENC-* | Data protection by design |
| 25.2 | PR-AWS-CLD-MIN-*, PR-AZR-CLD-MIN-* | Data minimization |

### Security of Processing (Article 32)
| Requirement | Rule Examples | Description |
|-------------|---------------|-------------|
| 32.1.a | PR-AWS-CLD-KMS-*, PR-AZR-CLD-KV-* | Encryption and pseudonymisation |
| 32.1.b | PR-AWS-CLD-BAK-*, PR-AZR-CLD-BAK-* | Confidentiality, integrity, availability |
| 32.1.c | PR-AWS-CLD-REC-*, PR-AZR-CLD-REC-* | Restore availability and access |
| 32.1.d | PR-AWS-CLD-TST-*, PR-AZR-CLD-TST-* | Testing and evaluation |

## HIPAA Mapping

### Administrative Safeguards
| Standard | Rule Examples | Description |
|----------|---------------|-------------|
| 164.308(a)(1) | PR-AWS-CLD-IAM-*, PR-AZR-CLD-IAM-* | Security Officer |
| 164.308(a)(3) | PR-AWS-CLD-ACC-*, PR-AZR-CLD-ACC-* | Workforce Training |
| 164.308(a)(4) | PR-AWS-CLD-AUD-*, PR-AZR-CLD-AUD-* | Information Access Management |

### Physical Safeguards
| Standard | Rule Examples | Description |
|----------|---------------|-------------|
| 164.310(a)(1) | PR-AWS-CLD-PHY-*, PR-AZR-CLD-PHY-* | Facility Access Controls |
| 164.310(d)(1) | PR-AWS-CLD-DEV-*, PR-AZR-CLD-DEV-* | Device and Media Controls |

### Technical Safeguards
| Standard | Rule Examples | Description |
|----------|---------------|-------------|
| 164.312(a)(1) | PR-AWS-CLD-IAM-*, PR-AZR-CLD-IAM-* | Access Control |
| 164.312(b) | PR-AWS-CLD-CT-*, PR-AZR-CLD-LOG-* | Audit Controls |
| 164.312(c)(1) | PR-AWS-CLD-INT-*, PR-AZR-CLD-INT-* | Integrity |
| 164.312(d) | PR-AWS-CLD-TRA-*, PR-AZR-CLD-TRA-* | Person or Entity Authentication |
| 164.312(e)(1) | PR-AWS-CLD-ENC-*, PR-AZR-CLD-ENC-* | Transmission Security |

## Compliance Reporting

### Automated Compliance Reporting
The repository supports automated generation of compliance reports through:

1. **Rule Tagging**: Each rule is tagged with applicable compliance frameworks
2. **Master Test Files**: Contain compliance mappings for automated reporting
3. **Utility Scripts**: Generate compliance-specific test suites
4. **Report Templates**: Standardized formats for different frameworks

### Custom Compliance Frameworks
To add support for new compliance frameworks:

1. **Update Rule Metadata**: Add new compliance tags to rule metadata
2. **Update Master Test Files**: Include new framework mappings
3. **Create Report Templates**: Develop framework-specific reporting templates
4. **Update Documentation**: Add framework details to this guide

### Compliance Validation
Regular validation ensures accuracy of compliance mappings:

1. **Quarterly Reviews**: Validate mappings against framework updates
2. **Expert Review**: Subject matter experts review rule-to-control mappings
3. **Automated Testing**: Verify rule behavior matches control requirements
4. **Documentation Updates**: Keep mappings current with framework changes

---

*This compliance framework mapping guide provides comprehensive coverage of how CSPM rules align with various security standards and regulatory requirements. For specific implementation guidance, refer to individual framework documentation and rule files.*