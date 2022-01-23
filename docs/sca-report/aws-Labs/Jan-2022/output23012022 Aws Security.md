# Automated Vulnerability Scan result and Static Code Analysis for Amazon Web Services Labs (Jan 2022)

## All Services

#### Compute: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Jan-2022/output23012022%20Aws%20Compute%20(Part1).md
#### Compute: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Jan-2022/output23012022%20Aws%20Compute%20(Part2).md
#### DataStore (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Jan-2022/output23012022%20Aws%20DataStore%20(Part1).md
#### DataStore (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Jan-2022/output23012022%20Aws%20DataStore%20(Part2).md
#### Management: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Jan-2022/output23012022%20Aws%20Management.md
#### Networking (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Jan-2022/output23012022%20Aws%20Networking%20(Part1).md
#### Networking (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Jan-2022/output23012022%20Aws%20Networking%20(Part2).md
#### Networking (Part3): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Jan-2022/output23012022%20Aws%20Networking%20(Part3).md
#### Networking (Part4): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Jan-2022/output23012022%20Aws%20Networking%20(Part4).md
#### Networking (Part5): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Jan-2022/output23012022%20Aws%20Networking%20(Part5).md
#### Networking (Part6): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Jan-2022/output23012022%20Aws%20Networking%20(Part6).md
#### Networking (Part7): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Jan-2022/output23012022%20Aws%20Networking%20(Part7).md
#### Security: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Jan-2022/output23012022%20Aws%20Security.md

## Aws Security Services

Source Repository: https://github.com/awslabs/aws-cloudformation-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac

## Compliance run Meta Data
| Title     | Description         |
|:----------|:--------------------|
| timestamp | 1642967962506       |
| snapshot  | master-snapshot_gen |
| container | scenario-aws-Labs   |
| test      | master-test.json    |

## Results

### Test ID - PR-AWS-CFR-KMS-001
Title: AWS Customer Master Key (CMK) rotation is not enabled\
Test Result: **passed**\
Description : This policy identifies Customer Master Keys (CMKs) that are not enabled with key rotation. AWS KMS (Key Management Service) allows customers to create master keys to encrypt sensitive data in different services. As a security best practice, it is important to rotate the keys periodically so that if the keys are compromised, the data in the underlying service is still secure with the new keys.\

#### Test Details
- eval: data.rule.kms_key_rotation
- id : PR-AWS-CFR-KMS-001

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function', 'custom::lambdatrig', 'aws::s3::bucket', 'aws::kms::key', 'aws::iam::managedpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-KMS-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/kms.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['NIST 800', 'CIS'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-KMS-001
Title: AWS Customer Master Key (CMK) rotation is not enabled\
Test Result: **passed**\
Description : This policy identifies Customer Master Keys (CMKs) that are not enabled with key rotation. AWS KMS (Key Management Service) allows customers to create master keys to encrypt sensitive data in different services. As a security best practice, it is important to rotate the keys periodically so that if the keys are compromised, the data in the underlying service is still secure with the new keys.\

#### Test Details
- eval: data.rule.kms_key_rotation
- id : PR-AWS-CFR-KMS-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroupingress', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function', 'aws::elasticloadbalancingv2::listener', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::cloudfront::distribution', 'aws::kms::key', 'aws::ec2::instance', 'custom::lambdaversion', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::listenerrule'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-KMS-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/kms.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['NIST 800', 'CIS'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-KMS-002
Title: AWS KMS Customer Managed Key not in use\
Test Result: **failed**\
Description : This policy identifies KMS Customer Managed Keys(CMKs) which are not usable. When you create a CMK, it is enabled by default. If you disable a CMK or schedule it for deletion makes it unusable, it cannot be used to encrypt or decrypt data and AWS KMS does not rotate the backing keys until you re-enable it.\

#### Test Details
- eval: data.rule.kms_key_state
- id : PR-AWS-CFR-KMS-002

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function', 'custom::lambdatrig', 'aws::s3::bucket', 'aws::kms::key', 'aws::iam::managedpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-KMS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/kms.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-KMS-002
Title: AWS KMS Customer Managed Key not in use\
Test Result: **passed**\
Description : This policy identifies KMS Customer Managed Keys(CMKs) which are not usable. When you create a CMK, it is enabled by default. If you disable a CMK or schedule it for deletion makes it unusable, it cannot be used to encrypt or decrypt data and AWS KMS does not rotate the backing keys until you re-enable it.\

#### Test Details
- eval: data.rule.kms_key_state
- id : PR-AWS-CFR-KMS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroupingress', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function', 'aws::elasticloadbalancingv2::listener', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::cloudfront::distribution', 'aws::kms::key', 'aws::ec2::instance', 'custom::lambdaversion', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::listenerrule'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-KMS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/kms.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-KMS-003
Title: Ensure no KMS key policy contain wildcard (*) principal\
Test Result: **passed**\
Description : This policy revents all user access to specific resource/s and actions\

#### Test Details
- eval: data.rule.kms_key_allow_all_principal
- id : PR-AWS-CFR-KMS-003

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function', 'custom::lambdatrig', 'aws::s3::bucket', 'aws::kms::key', 'aws::iam::managedpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-KMS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/kms.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-KMS-003
Title: Ensure no KMS key policy contain wildcard (*) principal\
Test Result: **passed**\
Description : This policy revents all user access to specific resource/s and actions\

#### Test Details
- eval: data.rule.kms_key_allow_all_principal
- id : PR-AWS-CFR-KMS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroupingress', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function', 'aws::elasticloadbalancingv2::listener', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::cloudfront::distribution', 'aws::kms::key', 'aws::ec2::instance', 'custom::lambdaversion', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::listenerrule'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-KMS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/kms.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-002
Title: Ensure no wildcards are specified in IAM policy with 'Action' section\
Test Result: **passed**\
Description : Using a wildcard in the Action element in a role's trust policy would allow any IAM user in an account to Manage all resources and a user can manipulate data. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_action
- id : PR-AWS-CFR-IAM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                      |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT35                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                              |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                           |
| type          | cloudformation                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws::iam::role', 'aws::cloudwatch::alarm', 'aws::neptune::dbparametergroup', 'aws::sns::subscription', 'aws::neptune::dbclusterparametergroup', 'aws::sns::topic', 'aws::neptune::dbcluster', 'aws::neptune::dbinstance', 'aws::iam::managedpolicy', 'aws::ec2::securitygroup', 'aws::neptune::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-IAM-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-002
Title: Ensure no wildcards are specified in IAM policy with 'Action' section\
Test Result: **passed**\
Description : Using a wildcard in the Action element in a role's trust policy would allow any IAM user in an account to Manage all resources and a user can manipulate data. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_action
- id : PR-AWS-CFR-IAM-002

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function', 'custom::lambdatrig', 'aws::s3::bucket', 'aws::kms::key', 'aws::iam::managedpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-IAM-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-002
Title: Ensure no wildcards are specified in IAM policy with 'Action' section\
Test Result: **passed**\
Description : Using a wildcard in the Action element in a role's trust policy would allow any IAM user in an account to Manage all resources and a user can manipulate data. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_action
- id : PR-AWS-CFR-IAM-002

#### Snapshots
| Title         | Description                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT107                                                                                                       |
| structure     | filesystem                                                                                                                     |
| reference     | master                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                            |
| collection    | cloudformationtemplate                                                                                                         |
| type          | cloudformation                                                                                                                 |
| region        |                                                                                                                                |
| resourceTypes | ['aws::iam::policy', 'aws::iam::managedpolicy', 'aws::iam::user']                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/solutions/read_only_user/read_only_user.json'] |

- masterTestId: PR-AWS-CFR-IAM-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT2                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                                                                                               |
| type          | cloudformation                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                      |
| resourceTypes | ['aws::iam::role', 'aws::autoscaling::launchconfiguration', 'aws::elasticloadbalancing::loadbalancer', 'aws::iam::instanceprofile', 'aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml']                                                                      |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT7                                                                                                                                   |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                   |
| type          | cloudformation                                                                                                                                           |
| region        |                                                                                                                                                          |
| resourceTypes | ['aws::iam::role']                                                                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/ExecutionRoleBuilder/example.template'] |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT8                                                                                                                                                |
| structure     | filesystem                                                                                                                                                            |
| reference     | master                                                                                                                                                                |
| source        | gitConnectorAwsLabs                                                                                                                                                   |
| collection    | cloudformationtemplate                                                                                                                                                |
| type          | cloudformation                                                                                                                                                        |
| region        |                                                                                                                                                                       |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::cloudformation::macro', 'aws::lambda::permission']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Macro.yaml'] |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT10                                                                                                                |
| structure     | filesystem                                                                                                                             |
| reference     | master                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                 |
| type          | cloudformation                                                                                                                         |
| region        |                                                                                                                                        |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::cloudformation::macro', 'aws::lambda::permission']                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python.yaml'] |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT12                                                                                                                        |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                                            |
| collection    | cloudformationtemplate                                                                                                                         |
| type          | cloudformation                                                                                                                                 |
| region        |                                                                                                                                                |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::cloudformation::macro', 'aws::lambda::permission']                                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string.yaml'] |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT14                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws::iam::role', 'aws::elasticache::subnetgroup', 'aws::ec2::subnet', 'custom::region', 'aws::lambda::function', 'aws::ec2::routetable', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::elasticache::parametergroup', 'aws::lambda::permission', 'aws::ec2::route', 'aws::ec2::securitygroup', 'aws::elasticache::replicationgroup', 'aws::ec2::vpc', 'aws::ec2::internetgateway'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                     |
| type          | cloudformation                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws::iam::role', 'aws::config::deliverychannel', 'aws::config::configurationrecorder', 'aws::ec2::volume', 'aws::lambda::function', 'aws::lambda::permission', 'aws::sns::topic', 'aws::sns::topicpolicy', 'aws::config::configrule', 'aws::s3::bucket'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT19                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['aws::iam::role', 'aws::ec2::subnet', 'aws::rds::dbclusterparametergroup', 'aws::ec2::internetgateway', 'aws::rds::dbsubnetgroup', 'aws::ec2::routetable', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::dms::replicationtask', 'aws::s3::bucket', 'aws::rds::dbinstance', 'aws::ec2::securitygroup', 'aws::dms::replicationsubnetgroup', 'aws::ec2::vpc', 'aws::ec2::route', 'aws::dms::replicationinstance'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT26                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws::iam::role', 'aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalingpolicy', 'aws::autoscaling::launchconfiguration', 'aws::ecs::service', 'aws::cloudwatch::alarm', 'aws::ecs::cluster', 'aws::logs::loggroup', 'aws::elasticloadbalancingv2::listener', 'aws::iam::instanceprofile', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroup', 'aws::ecs::taskdefinition', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancingv2::listenerrule', 'aws::applicationautoscaling::scalabletarget', 'aws::events::rule'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT27                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                                                                                               |
| type          | cloudformation                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                      |
| resourceTypes | ['aws::iam::role', 'aws::autoscaling::launchconfiguration', 'aws::elasticloadbalancing::loadbalancer', 'aws::iam::instanceprofile', 'aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBGuidedAutoScalingRollingUpgrade.yaml']                                                    |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT32                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::iam::role', 'aws::emr::cluster', 'aws::iam::instanceprofile']                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EMR/EMRCLusterGangliaWithSparkOrS3backedHbase.json'] |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT33                                                                                                               |
| structure     | filesystem                                                                                                                            |
| reference     | master                                                                                                                                |
| source        | gitConnectorAwsLabs                                                                                                                   |
| collection    | cloudformationtemplate                                                                                                                |
| type          | cloudformation                                                                                                                        |
| region        |                                                                                                                                       |
| resourceTypes | ['aws::iam::role', 'aws::emr::cluster', 'aws::iam::instanceprofile']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EMR/EMRClusterWithAdditioanalSecurityGroups.json'] |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                      |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT35                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                              |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                           |
| type          | cloudformation                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws::iam::role', 'aws::cloudwatch::alarm', 'aws::neptune::dbparametergroup', 'aws::sns::subscription', 'aws::neptune::dbclusterparametergroup', 'aws::sns::topic', 'aws::neptune::dbcluster', 'aws::neptune::dbinstance', 'aws::iam::managedpolicy', 'aws::ec2::securitygroup', 'aws::neptune::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT54                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::dhcpoptions', 'aws::logs::loggroup', 'aws::iam::instanceprofile', 'custom::adconnectorresource', 'aws::secretsmanager::secret', 'aws::ec2::vpcdhcpoptionsassociation', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function', 'custom::lambdatrig', 'aws::s3::bucket', 'aws::kms::key', 'aws::iam::managedpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT71                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['aws::iam::role', 'aws::ec2::subnet', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::routetable', 'aws::ec2::vpcendpoint', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::route'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT73                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                              |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws::iam::role', 'aws::ec2::subnet', 'aws::ec2::internetgateway', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::routetable', 'aws::ec2::vpcendpoint', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::securitygroup', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::route'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroupingress', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function', 'aws::elasticloadbalancingv2::listener', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::cloudfront::distribution', 'aws::kms::key', 'aws::ec2::instance', 'custom::lambdaversion', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::listenerrule'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT75                                                                                                                     |
| structure     | filesystem                                                                                                                                  |
| reference     | master                                                                                                                                      |
| source        | gitConnectorAwsLabs                                                                                                                         |
| collection    | cloudformationtemplate                                                                                                                      |
| type          | cloudformation                                                                                                                              |
| region        |                                                                                                                                             |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'custom::vpceinterface']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/createVPCInterfaceEndpoint/lambda_vpce_interface.json'] |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT77                                                                                                                              |
| structure     | filesystem                                                                                                                                           |
| reference     | master                                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                                               |
| type          | cloudformation                                                                                                                                       |
| region        |                                                                                                                                                      |
| resourceTypes | ['aws::iam::role', 'custom::directorysettingsresource', 'aws::lambda::function', 'aws::sns::topic', 'aws::logs::loggroup']                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/DirectoryServiceSettings/templates/DIRECTORY_SETTINGS.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT78                                                                                                  |
| structure     | filesystem                                                                                                               |
| reference     | master                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                      |
| collection    | cloudformationtemplate                                                                                                   |
| type          | cloudformation                                                                                                           |
| region        |                                                                                                                          |
| resourceTypes | ['aws::iam::role', 'aws::ssm::document', 'aws::iam::instanceprofile', 'aws::ec2::instance', 'aws::ec2::securitygroup']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT81                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                   |
| reference     | master                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::ec2::subnet', 'aws::ec2::internetgateway', 'aws::lambda::function', 'aws::ec2::routetable', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::eip', 'aws::ec2::natgateway', 'aws::ec2::vpc', 'aws::ec2::route'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/LambaStaticIP/lambda-static.cfn.yaml']                                                                                                                                                   |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT82                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                          |
| reference     | master                                                                                                                                                                              |
| source        | gitConnectorAwsLabs                                                                                                                                                                 |
| collection    | cloudformationtemplate                                                                                                                                                              |
| type          | cloudformation                                                                                                                                                                      |
| region        |                                                                                                                                                                                     |
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::lambda::function', 'aws::ec2::vpcgatewayattachment', 'custom::routetablelambda', 'aws::ec2::vpc', 'aws::ec2::route']          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/lambda-backed-cloudformation-custom-resources/get_vpc_main_route_table_id/RouteTable.template'] |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT83                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                                                                                                             |
| collection    | cloudformationtemplate                                                                                                                                                                                          |
| type          | cloudformation                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                 |
| resourceTypes | ['aws::iam::role', 'aws::ec2::dhcpoptions', 'aws::directoryservice::microsoftad', 'aws::iam::instanceprofile', 'aws::secretsmanager::secret', 'aws::ec2::vpcdhcpoptionsassociation', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ManagedAD/templates/MANAGEDAD.cfn.yaml']                                                                                    |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT89                                                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['aws::iam::role', 'aws::ec2::subnet', 'aws::ec2::internetgateway', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::routetable', 'aws::ec2::vpcendpoint', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::securitygroup', 'aws::ec2::instance', 'aws::ec2::vpc', 'custom::getpl', 'aws::ec2::route'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT90                                                                                                                   |
| structure     | filesystem                                                                                                                                |
| reference     | master                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                    |
| type          | cloudformation                                                                                                                            |
| region        |                                                                                                                                           |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::logs::loggroup']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/function-template.yaml'] |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT93                                                                                                                           |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                            |
| type          | cloudformation                                                                                                                                    |
| region        |                                                                                                                                                   |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::logs::loggroup']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/Templates/stackset-function-template.yaml'] |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT95                                                                                                                |
| structure     | filesystem                                                                                                                             |
| reference     | master                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                 |
| type          | cloudformation                                                                                                                         |
| region        |                                                                                                                                        |
| resourceTypes | ['aws::iam::role', 'aws::ec2::instance', 'aws::iam::instanceprofile']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/TaggingRootVolumesInEC2/Tagging_Root_volume.yaml'] |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT97                                                                                                                    |
| structure     | filesystem                                                                                                                                 |
| reference     | master                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                     |
| type          | cloudformation                                                                                                                             |
| region        |                                                                                                                                            |
| resourceTypes | ['aws::iam::role', 'aws::logs::loggroup', 'aws::ec2::flowlog']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsCloudWatch.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT99                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws::iam::role', 'aws::elasticache::subnetgroup', 'aws::ec2::subnet', 'custom::region', 'aws::lambda::function', 'aws::ec2::routetable', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::elasticache::parametergroup', 'aws::lambda::permission', 'aws::ec2::route', 'aws::ec2::securitygroup', 'aws::elasticache::replicationgroup', 'aws::ec2::vpc', 'aws::ec2::internetgateway'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT104                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                             |
| type          | cloudformation                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws::iam::role', 'aws::cloudwatch::alarm', 'aws::autoscaling::launchconfiguration', 'aws::efs::mounttarget', 'aws::elasticloadbalancing::loadbalancer', 'aws::efs::filesystem', 'aws::iam::instanceprofile', 'aws::autoscaling::scalingpolicy', 'aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EFS/efs_with_automount_to_ec2.json']                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-CFR-IAM-003

#### Snapshots
| Title         | Description                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT105                                                                                            |
| structure     | filesystem                                                                                                          |
| reference     | master                                                                                                              |
| source        | gitConnectorAwsLabs                                                                                                 |
| collection    | cloudformationtemplate                                                                                              |
| type          | cloudformation                                                                                                      |
| region        |                                                                                                                     |
| resourceTypes | ['aws::iam::role', 'aws::lambda::function']                                                                         |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/Lambda/LambdaSample.yaml'] |

- masterTestId: PR-AWS-CFR-IAM-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-004
Title: Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*'\
Test Result: **passed**\
Description : Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*' AWS only allows fully qualified ARNs or '*'. The above mentioned ARN is not supported in an identity-based policy\

#### Test Details
- eval: data.rule.iam_resource_format
- id : PR-AWS-CFR-IAM-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                      |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT35                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                              |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                           |
| type          | cloudformation                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws::iam::role', 'aws::cloudwatch::alarm', 'aws::neptune::dbparametergroup', 'aws::sns::subscription', 'aws::neptune::dbclusterparametergroup', 'aws::sns::topic', 'aws::neptune::dbcluster', 'aws::neptune::dbinstance', 'aws::iam::managedpolicy', 'aws::ec2::securitygroup', 'aws::neptune::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-IAM-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-004
Title: Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*'\
Test Result: **passed**\
Description : Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*' AWS only allows fully qualified ARNs or '*'. The above mentioned ARN is not supported in an identity-based policy\

#### Test Details
- eval: data.rule.iam_resource_format
- id : PR-AWS-CFR-IAM-004

#### Snapshots
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::iam::role', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function', 'custom::lambdatrig', 'aws::s3::bucket', 'aws::kms::key', 'aws::iam::managedpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-IAM-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-004
Title: Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*'\
Test Result: **passed**\
Description : Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*' AWS only allows fully qualified ARNs or '*'. The above mentioned ARN is not supported in an identity-based policy\

#### Test Details
- eval: data.rule.iam_resource_format
- id : PR-AWS-CFR-IAM-004

#### Snapshots
| Title         | Description                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT107                                                                                                       |
| structure     | filesystem                                                                                                                     |
| reference     | master                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                            |
| collection    | cloudformationtemplate                                                                                                         |
| type          | cloudformation                                                                                                                 |
| region        |                                                                                                                                |
| resourceTypes | ['aws::iam::policy', 'aws::iam::managedpolicy', 'aws::iam::user']                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/solutions/read_only_user/read_only_user.json'] |

- masterTestId: PR-AWS-CFR-IAM-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-005
Title: AWS IAM policy allows assume role permission across all services\
Test Result: **passed**\
Description : This policy identifies AWS IAM policy which allows assume role permission across all services. Typically, AssumeRole is used if you have multiple accounts and need to access resources from each account then you can create long term credentials in one account and then use temporary security credentials to access all the other accounts by assuming roles in those accounts.\

#### Test Details
- eval: data.rule.iam_assume_permission
- id : PR-AWS-CFR-IAM-005

#### Snapshots
| Title         | Description                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT34                                                                                                     |
| structure     | filesystem                                                                                                                  |
| reference     | master                                                                                                                      |
| source        | gitConnectorAwsLabs                                                                                                         |
| collection    | cloudformationtemplate                                                                                                      |
| type          | cloudformation                                                                                                              |
| region        |                                                                                                                             |
| resourceTypes | ['aws::iam::usertogroupaddition', 'aws::iam::user', 'aws::iam::group', 'aws::iam::accesskey', 'aws::iam::policy']           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/IAM/IAM_Users_Groups_and_Policies.yaml'] |

- masterTestId: PR-AWS-CFR-IAM-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description                                                                       |
|:-----------|:----------------------------------------------------------------------------------|
| cloud      | git                                                                               |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-005
Title: AWS IAM policy allows assume role permission across all services\
Test Result: **passed**\
Description : This policy identifies AWS IAM policy which allows assume role permission across all services. Typically, AssumeRole is used if you have multiple accounts and need to access resources from each account then you can create long term credentials in one account and then use temporary security credentials to access all the other accounts by assuming roles in those accounts.\

#### Test Details
- eval: data.rule.iam_assume_permission
- id : PR-AWS-CFR-IAM-005

#### Snapshots
| Title         | Description                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT107                                                                                                       |
| structure     | filesystem                                                                                                                     |
| reference     | master                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                            |
| collection    | cloudformationtemplate                                                                                                         |
| type          | cloudformation                                                                                                                 |
| region        |                                                                                                                                |
| resourceTypes | ['aws::iam::policy', 'aws::iam::managedpolicy', 'aws::iam::user']                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/solutions/read_only_user/read_only_user.json'] |

- masterTestId: PR-AWS-CFR-IAM-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: High

tags
| Title      | Description                                                                       |
|:-----------|:----------------------------------------------------------------------------------|
| cloud      | git                                                                               |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-006
Title: AWS IAM policy is overly permissive to all traffic via condition clause\
Test Result: **passed**\
Description : This policy identifies IAM policies that have a policy that is overly permissive to all traffic via condition clause. If any IAM policy statement with a condition containing 0.0.0.0/0 or ::/0, it allows all traffic to resources attached to that IAM policy. It is highly recommended to have the least privileged IAM policy to protect the data leakage and unauthorized access.\

#### Test Details
- eval: data.rule.iam_all_traffic
- id : PR-AWS-CFR-IAM-006

#### Snapshots
| Title         | Description                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT34                                                                                                     |
| structure     | filesystem                                                                                                                  |
| reference     | master                                                                                                                      |
| source        | gitConnectorAwsLabs                                                                                                         |
| collection    | cloudformationtemplate                                                                                                      |
| type          | cloudformation                                                                                                              |
| region        |                                                                                                                             |
| resourceTypes | ['aws::iam::usertogroupaddition', 'aws::iam::user', 'aws::iam::group', 'aws::iam::accesskey', 'aws::iam::policy']           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/IAM/IAM_Users_Groups_and_Policies.yaml'] |

- masterTestId: PR-AWS-CFR-IAM-006
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['CIS']            |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-006
Title: AWS IAM policy is overly permissive to all traffic via condition clause\
Test Result: **passed**\
Description : This policy identifies IAM policies that have a policy that is overly permissive to all traffic via condition clause. If any IAM policy statement with a condition containing 0.0.0.0/0 or ::/0, it allows all traffic to resources attached to that IAM policy. It is highly recommended to have the least privileged IAM policy to protect the data leakage and unauthorized access.\

#### Test Details
- eval: data.rule.iam_all_traffic
- id : PR-AWS-CFR-IAM-006

#### Snapshots
| Title         | Description                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT107                                                                                                       |
| structure     | filesystem                                                                                                                     |
| reference     | master                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                            |
| collection    | cloudformationtemplate                                                                                                         |
| type          | cloudformation                                                                                                                 |
| region        |                                                                                                                                |
| resourceTypes | ['aws::iam::policy', 'aws::iam::managedpolicy', 'aws::iam::user']                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/solutions/read_only_user/read_only_user.json'] |

- masterTestId: PR-AWS-CFR-IAM-006
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['CIS']            |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-007
Title: AWS IAM policy allows full administrative privileges\
Test Result: **passed**\
Description : This policy identifies IAM policies with full administrative privileges. IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege like granting only the permissions required to perform a task. Determine what users need to do and then craft policies for them that let the users perform only those tasks, instead of allowing full administrative privileges.\

#### Test Details
- eval: data.rule.iam_administrative_privileges
- id : PR-AWS-CFR-IAM-007

#### Snapshots
| Title         | Description                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT34                                                                                                     |
| structure     | filesystem                                                                                                                  |
| reference     | master                                                                                                                      |
| source        | gitConnectorAwsLabs                                                                                                         |
| collection    | cloudformationtemplate                                                                                                      |
| type          | cloudformation                                                                                                              |
| region        |                                                                                                                             |
| resourceTypes | ['aws::iam::usertogroupaddition', 'aws::iam::user', 'aws::iam::group', 'aws::iam::accesskey', 'aws::iam::policy']           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/IAM/IAM_Users_Groups_and_Policies.yaml'] |

- masterTestId: PR-AWS-CFR-IAM-007
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Low

tags
| Title      | Description                                                                       |
|:-----------|:----------------------------------------------------------------------------------|
| cloud      | git                                                                               |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-007
Title: AWS IAM policy allows full administrative privileges\
Test Result: **passed**\
Description : This policy identifies IAM policies with full administrative privileges. IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege like granting only the permissions required to perform a task. Determine what users need to do and then craft policies for them that let the users perform only those tasks, instead of allowing full administrative privileges.\

#### Test Details
- eval: data.rule.iam_administrative_privileges
- id : PR-AWS-CFR-IAM-007

#### Snapshots
| Title         | Description                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT107                                                                                                       |
| structure     | filesystem                                                                                                                     |
| reference     | master                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                            |
| collection    | cloudformationtemplate                                                                                                         |
| type          | cloudformation                                                                                                                 |
| region        |                                                                                                                                |
| resourceTypes | ['aws::iam::policy', 'aws::iam::managedpolicy', 'aws::iam::user']                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/solutions/read_only_user/read_only_user.json'] |

- masterTestId: PR-AWS-CFR-IAM-007
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Low

tags
| Title      | Description                                                                       |
|:-----------|:----------------------------------------------------------------------------------|
| cloud      | git                                                                               |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-IAM-008
Title: Ensure IAM groups contains at least one IAM user\
Test Result: **passed**\
Description : Ensure that your Amazon Identity and Access Management (IAM) users are members of at least one IAM group in order to adhere to IAM security best practices\

#### Test Details
- eval: data.rule.iam_user_group_attach
- id : PR-AWS-CFR-IAM-008

#### Snapshots
| Title         | Description                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT34                                                                                                     |
| structure     | filesystem                                                                                                                  |
| reference     | master                                                                                                                      |
| source        | gitConnectorAwsLabs                                                                                                         |
| collection    | cloudformationtemplate                                                                                                      |
| type          | cloudformation                                                                                                              |
| region        |                                                                                                                             |
| resourceTypes | ['aws::iam::usertogroupaddition', 'aws::iam::user', 'aws::iam::group', 'aws::iam::accesskey', 'aws::iam::policy']           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/IAM/IAM_Users_Groups_and_Policies.yaml'] |

- masterTestId: PR-AWS-CFR-IAM-008
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Low

tags
| Title      | Description                                                                       |
|:-----------|:----------------------------------------------------------------------------------|
| cloud      | git                                                                               |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2'] |
| service    | ['cloudformation']                                                                |
----------------------------------------------------------------

