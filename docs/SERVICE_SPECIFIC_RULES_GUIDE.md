# Service-Specific Rules Guide

## AWS Rules Breakdown

### AWS Storage Services

#### S3 (Simple Storage Service)
**Rule Categories:**
- **Access Control**: Bucket policies, ACLs, public access blocks
- **Encryption**: Server-side encryption, KMS key usage
- **Logging**: Access logging, CloudTrail integration
- **Versioning**: Object versioning, lifecycle policies
- **Compliance**: Data retention, cross-region replication

**Key Rules:**
- `PR-AWS-CFR-S3-001`: Access logging not enabled
- `PR-AWS-CFR-S3-002`: Bucket policy allows public access
- `PR-AWS-CFR-S3-003`: Server-side encryption not configured
- `PR-AWS-CFR-S3-004`: Versioning not enabled
- `PR-AWS-CFR-S3-005`: Public read/write access enabled

**Resource Types Covered:**
- `aws::s3::bucket`
- `aws::s3::bucketpolicy`
- `aws::s3::bucketnotification`

#### EBS (Elastic Block Store)
**Rule Categories:**
- **Encryption**: Volume encryption, snapshot encryption
- **Backup**: Snapshot policies, retention
- **Performance**: Volume types, IOPS configuration

**Key Rules:**
- `PR-AWS-CFR-EBS-001`: Unencrypted EBS volumes
- `PR-AWS-CFR-EBS-002`: Missing snapshot backup
- `PR-AWS-CFR-EBS-003`: Public snapshots

### AWS Compute Services

#### EC2 (Elastic Compute Cloud)
**Rule Categories:**
- **Security Groups**: Ingress/egress rules, port restrictions
- **Instance Configuration**: AMI security, metadata service
- **Network**: VPC placement, subnet configuration
- **Monitoring**: CloudWatch integration, detailed monitoring

**Key Rules:**
- `PR-AWS-CFR-EC2-001`: Security group allows unrestricted access
- `PR-AWS-CFR-EC2-002`: Instance not in VPC
- `PR-AWS-CFR-EC2-003`: Detailed monitoring disabled
- `PR-AWS-CFR-EC2-004`: Public IP assignment

#### Lambda
**Rule Categories:**
- **Runtime Security**: Function permissions, execution role
- **Network**: VPC configuration, security groups
- **Monitoring**: CloudWatch logs, X-Ray tracing
- **Resource Limits**: Memory, timeout configuration

**Key Rules:**
- `PR-AWS-CFR-LAM-001`: Function not in VPC
- `PR-AWS-CFR-LAM-002`: Overly permissive execution role
- `PR-AWS-CFR-LAM-003`: CloudWatch logs not configured

### AWS Database Services

#### RDS (Relational Database Service)
**Rule Categories:**
- **Encryption**: Data at rest, data in transit
- **Backup**: Automated backups, point-in-time recovery
- **Network**: VPC placement, security groups
- **Monitoring**: Performance insights, enhanced monitoring

**Key Rules:**
- `PR-AWS-CFR-RDS-001`: Database not encrypted
- `PR-AWS-CFR-RDS-002`: Automated backup disabled
- `PR-AWS-CFR-RDS-003`: Database publicly accessible
- `PR-AWS-CFR-RDS-004`: Multi-AZ deployment disabled

#### DynamoDB
**Rule Categories:**
- **Encryption**: Server-side encryption, KMS keys
- **Backup**: Point-in-time recovery, on-demand backup
- **Access Control**: IAM policies, resource-based policies
- **Monitoring**: CloudWatch metrics, contributor insights

### AWS Security Services

#### IAM (Identity and Access Management)
**Rule Categories:**
- **User Management**: Password policies, MFA requirements
- **Role Configuration**: Trust policies, permission boundaries
- **Policy Analysis**: Overly permissive policies, unused permissions
- **Access Keys**: Rotation, usage monitoring

**Key Rules:**
- `PR-AWS-CFR-IAM-001`: Password policy not configured
- `PR-AWS-CFR-IAM-002`: Root account usage
- `PR-AWS-CFR-IAM-003`: MFA not enabled
- `PR-AWS-CFR-IAM-004`: Overly permissive policies

#### KMS (Key Management Service)
**Rule Categories:**
- **Key Rotation**: Automatic rotation, manual rotation
- **Key Policies**: Access control, cross-account access
- **Key Usage**: Encryption context, key scheduling
- **Monitoring**: CloudTrail logging, key usage metrics

**Key Rules:**
- `PR-AWS-CFR-KMS-001`: Key rotation not enabled
- `PR-AWS-CFR-KMS-002`: Key not in use
- `PR-AWS-CFR-KMS-003`: Key scheduled for deletion

## Azure Rules Breakdown

### Azure Storage Services

#### Storage Accounts
**Rule Categories:**
- **Access Control**: Shared access signatures, RBAC
- **Encryption**: Storage service encryption, customer-managed keys
- **Network**: Firewall rules, virtual network service endpoints
- **Monitoring**: Storage analytics, diagnostic settings

**Key Rules:**
- `PR-AZR-CLD-SA-001`: Storage account allows public access
- `PR-AZR-CLD-SA-002`: Encryption not configured
- `PR-AZR-CLD-SA-003`: Secure transfer not required
- `PR-AZR-CLD-SA-004`: Network access not restricted

#### Managed Disks
**Rule Categories:**
- **Encryption**: Disk encryption, customer-managed keys
- **Backup**: Disk snapshots, backup policies
- **Performance**: Disk types, caching configuration

### Azure Compute Services

#### Virtual Machines
**Rule Categories:**
- **Security**: Endpoint protection, security extensions
- **Network**: Network security groups, public IP assignment
- **Monitoring**: Boot diagnostics, performance monitoring
- **Backup**: VM backup, disaster recovery

**Key Rules:**
- `PR-AZR-CLD-VM-001`: VM not protected by endpoint protection
- `PR-AZR-CLD-VM-002`: Network security group not configured
- `PR-AZR-CLD-VM-003`: Boot diagnostics disabled
- `PR-AZR-CLD-VM-004`: VM backup not configured

#### AKS (Azure Kubernetes Service)
**Rule Categories:**
- **RBAC**: Role-based access control, Azure AD integration
- **Network**: Network policies, private clusters
- **Security**: Pod security policies, admission controllers
- **Monitoring**: Container insights, log analytics

### Azure Database Services

#### SQL Database
**Rule Categories:**
- **Security**: Transparent data encryption, firewall rules
- **Auditing**: SQL auditing, threat detection
- **Backup**: Automated backups, long-term retention
- **Performance**: Query performance insights, automatic tuning

**Key Rules:**
- `PR-AZR-CLD-SQL-001`: Transparent data encryption disabled
- `PR-AZR-CLD-SQL-002`: SQL auditing not configured
- `PR-AZR-CLD-SQL-003`: Threat detection disabled
- `PR-AZR-CLD-SQL-004`: Firewall allows all IPs

### Azure Security Services

#### Key Vault
**Rule Categories:**
- **Access Policies**: Key permissions, secret permissions
- **Network**: Firewall rules, private endpoints
- **Monitoring**: Diagnostic settings, access logging
- **Backup**: Soft delete, purge protection

**Key Rules:**
- `PR-AZR-CLD-KV-001`: Key Vault access not restricted
- `PR-AZR-CLD-KV-002`: Soft delete not enabled
- `PR-AZR-CLD-KV-003`: Purge protection disabled
- `PR-AZR-CLD-KV-004`: Diagnostic settings not configured

## Google Cloud Rules Breakdown

### GCP Storage Services

#### Cloud Storage
**Rule Categories:**
- **Access Control**: IAM policies, bucket policies
- **Encryption**: Customer-managed encryption keys
- **Versioning**: Object versioning, lifecycle management
- **Monitoring**: Access logging, usage metrics

**Key Rules:**
- `PR-GCP-CLD-BKT-001`: Bucket not encrypted with customer-managed key
- `PR-GCP-CLD-BKT-002`: Object versioning disabled for log buckets
- `PR-GCP-CLD-BKT-003`: Bucket allows public access
- `PR-GCP-CLD-BKT-004`: Uniform bucket-level access disabled

#### Persistent Disks
**Rule Categories:**
- **Encryption**: Disk encryption, customer-managed keys
- **Backup**: Disk snapshots, snapshot scheduling
- **Performance**: Disk types, regional persistent disks

### GCP Compute Services

#### Compute Engine
**Rule Categories:**
- **Security**: OS Login, Shielded VMs
- **Network**: Firewall rules, VPC configuration
- **Monitoring**: Stackdriver integration, logging
- **Access**: Service accounts, SSH keys

**Key Rules:**
- `PR-GCP-CLD-CE-001`: OS Login not enabled
- `PR-GCP-CLD-CE-002`: Shielded VM not configured
- `PR-GCP-CLD-CE-003`: Default service account used
- `PR-GCP-CLD-CE-004`: IP forwarding enabled

#### GKE (Google Kubernetes Engine)
**Rule Categories:**
- **Security**: Workload Identity, Binary Authorization
- **Network**: Private clusters, authorized networks
- **Monitoring**: Stackdriver Kubernetes Engine Monitoring
- **Node Security**: Container-Optimized OS, automatic upgrades

### GCP Database Services

#### Cloud SQL
**Rule Categories:**
- **Security**: SSL/TLS encryption, authorized networks
- **Backup**: Automated backups, point-in-time recovery
- **High Availability**: Regional persistent disks, failover replicas
- **Monitoring**: Query insights, performance monitoring

**Key Rules:**
- `PR-GCP-CLD-SQL-001`: SSL not required
- `PR-GCP-CLD-SQL-002`: Automated backup disabled
- `PR-GCP-CLD-SQL-003`: Database publicly accessible
- `PR-GCP-CLD-SQL-004`: Binary logging disabled

## Kubernetes Rules Breakdown

### RBAC (Role-Based Access Control)
**Rule Categories:**
- **Roles**: ClusterRole, Role permissions
- **Bindings**: RoleBinding, ClusterRoleBinding
- **Service Accounts**: Default service account usage
- **Secrets Access**: Minimize access to secrets

**Key Rules:**
- `PR-K8S-0001`: Minimize access to secrets (RBAC)
- `PR-K8S-0002`: Minimize wildcard use in Roles and ClusterRoles
- `PR-K8S-0003`: Default service account should not be used
- `PR-K8S-0004`: Minimize access to create pods

### Pod Security
**Rule Categories:**
- **Security Context**: runAsNonRoot, readOnlyRootFilesystem
- **Capabilities**: Drop all capabilities, add specific ones
- **Resource Limits**: CPU, memory limits and requests
- **Network**: hostNetwork, hostPID, hostIPC restrictions

**Key Rules:**
- `PR-K8S-0008`: Do not run containers as root
- `PR-K8S-0009`: Use read-only root filesystem
- `PR-K8S-0010`: Drop all capabilities
- `PR-K8S-0011`: Set resource limits

### Network Security
**Rule Categories:**
- **Network Policies**: Ingress, egress rules
- **Service Configuration**: Service types, port restrictions
- **Ingress**: TLS configuration, host restrictions
- **Pod Communication**: Inter-pod communication rules

**Key Rules:**
- `PR-K8S-0015`: Default deny all ingress traffic
- `PR-K8S-0016`: Default deny all egress traffic
- `PR-K8S-0017`: Use TLS for ingress
- `PR-K8S-0018`: Restrict service types

### Configuration Security
**Rule Categories:**
- **Secrets Management**: Secret usage, encryption at rest
- **ConfigMaps**: Sensitive data in ConfigMaps
- **Environment Variables**: Secrets in environment variables
- **Volume Mounts**: hostPath restrictions

**Key Rules:**
- `PR-K8S-0020`: Do not use hostPath volumes
- `PR-K8S-0021`: Secrets should not be in environment variables
- `PR-K8S-0022`: ConfigMaps should not contain sensitive data
- `PR-K8S-0023`: Use secrets for sensitive data

## Rule Severity Levels

### Critical
- **Impact**: Immediate security risk, data exposure
- **Examples**: Public S3 buckets, unencrypted databases, overly permissive IAM policies
- **Action Required**: Immediate remediation

### High
- **Impact**: Significant security risk, compliance violation
- **Examples**: Missing encryption, disabled logging, weak authentication
- **Action Required**: Remediate within 24-48 hours

### Medium
- **Impact**: Moderate security risk, best practice violation
- **Examples**: Missing monitoring, suboptimal configuration, resource waste
- **Action Required**: Remediate within 1 week

### Low
- **Impact**: Minor security concern, optimization opportunity
- **Examples**: Missing tags, unused resources, documentation gaps
- **Action Required**: Remediate during next maintenance window

## Compliance Framework Mapping

### CIS Benchmarks
- **AWS**: CIS Amazon Web Services Foundations Benchmark
- **Azure**: CIS Microsoft Azure Foundations Benchmark
- **GCP**: CIS Google Cloud Platform Foundation Benchmark
- **Kubernetes**: CIS Kubernetes Benchmark

### NIST Frameworks
- **NIST 800-53**: Security and Privacy Controls
- **NIST CSF**: Cybersecurity Framework
- **NIST 800-171**: Controlled Unclassified Information

### Industry Standards
- **ISO 27001**: Information Security Management
- **SOC 2**: Service Organization Control 2
- **PCI DSS**: Payment Card Industry Data Security Standard

### Regulatory Compliance
- **GDPR**: General Data Protection Regulation
- **HIPAA**: Health Insurance Portability and Accountability Act
- **CCPA**: California Consumer Privacy Act

## Best Practices for Rule Implementation

### Rule Design Principles
1. **Single Responsibility**: Each rule should check one specific security control
2. **Clear Naming**: Rule names should clearly indicate what is being checked
3. **Comprehensive Coverage**: Rules should cover all relevant resource types
4. **Performance**: Rules should be efficient and not cause performance issues

### Testing Guidelines
1. **Positive Testing**: Verify rules pass when configuration is correct
2. **Negative Testing**: Verify rules fail when configuration is incorrect
3. **Edge Cases**: Test boundary conditions and unusual configurations
4. **Performance Testing**: Ensure rules execute efficiently at scale

### Documentation Standards
1. **Rule Description**: Clear explanation of what the rule checks
2. **Remediation Steps**: Step-by-step instructions to fix issues
3. **Compliance Mapping**: Reference to relevant compliance frameworks
4. **Examples**: Sample configurations that pass and fail the rule

---

*This guide provides detailed information about service-specific rules across all supported cloud providers. For implementation details, refer to individual rule files and the main documentation.*