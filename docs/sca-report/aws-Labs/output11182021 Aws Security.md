# Automated Vulnerability Scan result and Static Code Analysis for Aws Labs (Nov 2021)


## AWS Security Services

Source Repository: https://github.com/awslabs/aws-cloudformation-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac

## Compliance run Meta Data
| Title     | Description         |
|:----------|:--------------------|
| timestamp | 1637184834855       |
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
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::iam::managedpolicy', 'aws::kms::alias', 'custom::lambdatrig', 'aws::iam::role', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_KMS_1
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
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroupingress', 'custom::lambdaversion', 'aws::kms::alias', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::ec2::securitygroupegress', 'aws::lambda::function', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::instance'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_KMS_1
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
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::iam::managedpolicy', 'aws::kms::alias', 'custom::lambdatrig', 'aws::iam::role', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_KMS_2
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
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroupingress', 'custom::lambdaversion', 'aws::kms::alias', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::ec2::securitygroupegress', 'aws::lambda::function', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::instance'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_KMS_2
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
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::iam::managedpolicy', 'aws::kms::alias', 'custom::lambdatrig', 'aws::iam::role', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_KMS_3
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
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroupingress', 'custom::lambdaversion', 'aws::kms::alias', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::ec2::securitygroupegress', 'aws::lambda::function', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::instance'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_KMS_3
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


### Test ID - PR-AWS-CFR-SM-001
Title: Ensure that Secrets Manager secret is encrypted using KMS\
Test Result: **passed**\
Description : Ensure that your Amazon Secrets Manager secrets (i.e. database credentials, API keys, OAuth tokens, etc) are encrypted with Amazon KMS Customer Master Keys instead of default encryption keys that Secrets Manager service creates for you, in order to have a more control over secret data encryption and decryption process\

#### Test Details
- eval: data.rule.secret_manager_kms
- id : PR-AWS-CFR-SM-001

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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::secretsmanager::secret', 'aws::ec2::vpcdhcpoptionsassociation', 'custom::adconnectorresource', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::lambda::function', 'aws::ec2::dhcpoptions', 'aws::logs::loggroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: TEST_ALL_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SM-001
Title: Ensure that Secrets Manager secret is encrypted using KMS\
Test Result: **passed**\
Description : Ensure that your Amazon Secrets Manager secrets (i.e. database credentials, API keys, OAuth tokens, etc) are encrypted with Amazon KMS Customer Master Keys instead of default encryption keys that Secrets Manager service creates for you, in order to have a more control over secret data encryption and decryption process\

#### Test Details
- eval: data.rule.secret_manager_kms
- id : PR-AWS-CFR-SM-001

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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::secretsmanager::secret', 'aws::ec2::vpcdhcpoptionsassociation', 'aws::directoryservice::microsoftad', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ec2::dhcpoptions'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ManagedAD/templates/MANAGEDAD.cfn.yaml']                                                                                    |

- masterTestId: TEST_ALL_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego)
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
| resourceTypes | ['aws::sns::topic', 'aws::sns::subscription', 'aws::iam::managedpolicy', 'aws::neptune::dbinstance', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::neptune::dbclusterparametergroup', 'aws::cloudwatch::alarm', 'aws::neptune::dbsubnetgroup', 'aws::neptune::dbcluster', 'aws::neptune::dbparametergroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: TEST_IAM_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
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
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT69                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                                                       |
| type          | cloudformation                                                                                                                                                               |
| region        |                                                                                                                                                                              |
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::iam::managedpolicy', 'aws::kms::alias', 'custom::lambdatrig', 'aws::iam::role', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_IAM_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
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
| Title         | Description                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT107                                                                                                       |
| structure     | filesystem                                                                                                                     |
| reference     | master                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                            |
| collection    | cloudformationtemplate                                                                                                         |
| type          | cloudformation                                                                                                                 |
| region        |                                                                                                                                |
| resourceTypes | ['aws::iam::managedpolicy', 'aws::iam::user', 'aws::iam::policy']                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/solutions/read_only_user/read_only_user.json'] |

- masterTestId: TEST_IAM_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::iam::role', 'aws::autoscaling::autoscalinggroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml']                                                                      |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::lambda::permission', 'aws::lambda::function', 'aws::cloudformation::macro', 'aws::iam::role']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Macro.yaml'] |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::lambda::permission', 'aws::lambda::function', 'aws::cloudformation::macro', 'aws::iam::role']                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python.yaml'] |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::lambda::permission', 'aws::lambda::function', 'aws::cloudformation::macro', 'aws::iam::role']                                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string.yaml'] |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::ec2::route', 'aws::lambda::permission', 'custom::region', 'aws::ec2::vpcgatewayattachment', 'aws::elasticache::parametergroup', 'aws::ec2::vpc', 'aws::ec2::routetable', 'aws::elasticache::subnetgroup', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::lambda::function', 'aws::ec2::subnet', 'aws::elasticache::replicationgroup', 'aws::ec2::internetgateway', 'aws::ec2::subnetroutetableassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::s3::bucket', 'aws::lambda::permission', 'aws::iam::role', 'aws::config::configurationrecorder', 'aws::config::deliverychannel', 'aws::lambda::function', 'aws::config::configrule', 'aws::ec2::volume', 'aws::sns::topicpolicy', 'aws::sns::topic'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::ec2::route', 'aws::s3::bucket', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::ec2::vpcgatewayattachment', 'aws::rds::dbsubnetgroup', 'aws::ec2::vpc', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::rds::dbclusterparametergroup', 'aws::rds::dbinstance', 'aws::iam::role', 'aws::dms::replicationsubnetgroup', 'aws::ec2::subnet', 'aws::dms::endpoint', 'aws::dms::replicationtask', 'aws::ec2::internetgateway', 'aws::ec2::subnetroutetableassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroupingress', 'aws::ecs::cluster', 'aws::autoscaling::autoscalinggroup', 'aws::ecs::service', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::listener', 'aws::autoscaling::launchconfiguration', 'aws::events::rule', 'aws::iam::role', 'aws::cloudwatch::alarm', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::elasticloadbalancingv2::listenerrule', 'aws::applicationautoscaling::scalabletarget'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::iam::role', 'aws::autoscaling::autoscalinggroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBGuidedAutoScalingRollingUpgrade.yaml']                                                    |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::emr::cluster', 'aws::iam::instanceprofile', 'aws::iam::role']                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EMR/EMRCLusterGangliaWithSparkOrS3backedHbase.json'] |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::emr::cluster', 'aws::iam::instanceprofile', 'aws::iam::role']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EMR/EMRClusterWithAdditioanalSecurityGroups.json'] |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::sns::topic', 'aws::sns::subscription', 'aws::iam::managedpolicy', 'aws::neptune::dbinstance', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::neptune::dbclusterparametergroup', 'aws::cloudwatch::alarm', 'aws::neptune::dbsubnetgroup', 'aws::neptune::dbcluster', 'aws::neptune::dbparametergroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::secretsmanager::secret', 'aws::ec2::vpcdhcpoptionsassociation', 'custom::adconnectorresource', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::lambda::function', 'aws::ec2::dhcpoptions', 'aws::logs::loggroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::iam::managedpolicy', 'aws::kms::alias', 'custom::lambdatrig', 'aws::iam::role', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::ec2::route', 'aws::iam::instanceprofile', 'aws::ec2::instance', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::ec2::routetable', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::vpcendpoint', 'aws::ec2::internetgateway', 'aws::ec2::subnetroutetableassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::ec2::route', 'aws::iam::instanceprofile', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::ec2::routetable', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::internetgateway', 'aws::ec2::subnetroutetableassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroupingress', 'custom::lambdaversion', 'aws::kms::alias', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::ec2::securitygroupegress', 'aws::lambda::function', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::instance'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['custom::vpceinterface', 'aws::lambda::function', 'aws::iam::role']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/createVPCInterfaceEndpoint/lambda_vpce_interface.json'] |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::sns::topic', 'aws::iam::role', 'aws::lambda::function', 'custom::directorysettingsresource', 'aws::logs::loggroup']                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/DirectoryServiceSettings/templates/DIRECTORY_SETTINGS.cfn.yaml'] |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::ssm::document', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ec2::instance']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::ec2::natgateway', 'aws::ec2::route', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::ec2::routetable', 'aws::iam::role', 'aws::lambda::function', 'aws::ec2::subnet', 'aws::ec2::eip', 'aws::ec2::internetgateway', 'aws::ec2::subnetroutetableassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/LambaStaticIP/lambda-static.cfn.yaml']                                                                                                                                                   |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::ec2::route', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::iam::role', 'aws::lambda::function', 'custom::routetablelambda', 'aws::ec2::internetgateway']          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/lambda-backed-cloudformation-custom-resources/get_vpc_main_route_table_id/RouteTable.template'] |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::secretsmanager::secret', 'aws::ec2::vpcdhcpoptionsassociation', 'aws::directoryservice::microsoftad', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ec2::dhcpoptions'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ManagedAD/templates/MANAGEDAD.cfn.yaml']                                                                                    |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::ec2::route', 'aws::iam::instanceprofile', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::ec2::routetable', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'custom::getpl', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::internetgateway', 'aws::ec2::subnetroutetableassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::lambda::function', 'aws::logs::loggroup', 'aws::iam::role']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/function-template.yaml'] |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::lambda::function', 'aws::logs::loggroup', 'aws::iam::role']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/Templates/stackset-function-template.yaml'] |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::iam::role', 'aws::ec2::instance']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/TaggingRootVolumesInEC2/Tagging_Root_volume.yaml'] |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::ec2::flowlog', 'aws::logs::loggroup', 'aws::iam::role']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsCloudWatch.cfn.yaml'] |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::ec2::route', 'aws::lambda::permission', 'custom::region', 'aws::ec2::vpcgatewayattachment', 'aws::elasticache::parametergroup', 'aws::ec2::vpc', 'aws::ec2::routetable', 'aws::elasticache::subnetgroup', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::lambda::function', 'aws::ec2::subnet', 'aws::elasticache::replicationgroup', 'aws::ec2::internetgateway', 'aws::ec2::subnetroutetableassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::cloudwatch::alarm', 'aws::efs::filesystem', 'aws::iam::role', 'aws::autoscaling::launchconfiguration', 'aws::efs::mounttarget', 'aws::autoscaling::scalingpolicy', 'aws::autoscaling::autoscalinggroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EFS/efs_with_automount_to_ec2.json']                                                                                                                                                                                      |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::lambda::function', 'aws::iam::role']                                                                         |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/Lambda/LambdaSample.yaml'] |

- masterTestId: TEST_IAM_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::sns::topic', 'aws::sns::subscription', 'aws::iam::managedpolicy', 'aws::neptune::dbinstance', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::neptune::dbclusterparametergroup', 'aws::cloudwatch::alarm', 'aws::neptune::dbsubnetgroup', 'aws::neptune::dbcluster', 'aws::neptune::dbparametergroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: TEST_IAM_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::iam::managedpolicy', 'aws::kms::alias', 'custom::lambdatrig', 'aws::iam::role', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_IAM_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::iam::managedpolicy', 'aws::iam::user', 'aws::iam::policy']                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/solutions/read_only_user/read_only_user.json'] |

- masterTestId: TEST_IAM_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::iam::group', 'aws::iam::usertogroupaddition', 'aws::iam::user', 'aws::iam::accesskey', 'aws::iam::policy']           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/IAM/IAM_Users_Groups_and_Policies.yaml'] |

- masterTestId: TEST_IAM_5
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::iam::managedpolicy', 'aws::iam::user', 'aws::iam::policy']                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/solutions/read_only_user/read_only_user.json'] |

- masterTestId: TEST_IAM_5
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
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
| Title         | Description                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT34                                                                                                     |
| structure     | filesystem                                                                                                                  |
| reference     | master                                                                                                                      |
| source        | gitConnectorAwsLabs                                                                                                         |
| collection    | cloudformationtemplate                                                                                                      |
| type          | cloudformation                                                                                                              |
| region        |                                                                                                                             |
| resourceTypes | ['aws::iam::group', 'aws::iam::usertogroupaddition', 'aws::iam::user', 'aws::iam::accesskey', 'aws::iam::policy']           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/IAM/IAM_Users_Groups_and_Policies.yaml'] |

- masterTestId: TEST_IAM_6
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
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
| resourceTypes | ['aws::iam::managedpolicy', 'aws::iam::user', 'aws::iam::policy']                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/solutions/read_only_user/read_only_user.json'] |

- masterTestId: TEST_IAM_6
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
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
| resourceTypes | ['aws::iam::group', 'aws::iam::usertogroupaddition', 'aws::iam::user', 'aws::iam::accesskey', 'aws::iam::policy']           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/IAM/IAM_Users_Groups_and_Policies.yaml'] |

- masterTestId: TEST_IAM_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
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
| Title         | Description                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT107                                                                                                       |
| structure     | filesystem                                                                                                                     |
| reference     | master                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                            |
| collection    | cloudformationtemplate                                                                                                         |
| type          | cloudformation                                                                                                                 |
| region        |                                                                                                                                |
| resourceTypes | ['aws::iam::managedpolicy', 'aws::iam::user', 'aws::iam::policy']                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/solutions/read_only_user/read_only_user.json'] |

- masterTestId: TEST_IAM_7
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
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
| resourceTypes | ['aws::iam::group', 'aws::iam::usertogroupaddition', 'aws::iam::user', 'aws::iam::accesskey', 'aws::iam::policy']           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/IAM/IAM_Users_Groups_and_Policies.yaml'] |

- masterTestId: TEST_IAM_8
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------

