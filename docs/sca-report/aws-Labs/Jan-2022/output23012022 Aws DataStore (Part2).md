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

## Aws Data Store (Part2) Services

Source Repository: https://github.com/awslabs/aws-cloudformation-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac

## Compliance run Meta Data
| Title     | Description         |
|:----------|:--------------------|
| timestamp | 1642971427651       |
| snapshot  | master-snapshot_gen |
| container | scenario-aws-Labs   |
| test      | master-test.json    |

## Results

### Test ID - PR-AWS-CFR-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-CFR-S3-015

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
| resourceTypes | ['aws::sns::topic', 'aws::s3::bucket', 'aws::config::configurationrecorder', 'aws::config::configrule', 'aws::iam::role', 'aws::lambda::permission', 'aws::ec2::volume', 'aws::sns::topicpolicy', 'aws::config::deliverychannel', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-S3-015
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['NIST 800', 'GDPR'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-CFR-S3-015

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-S3-015
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['NIST 800', 'GDPR'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-CFR-S3-015

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::autoscaling::launchconfiguration'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: PR-AWS-CFR-S3-015
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['NIST 800', 'GDPR'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-CFR-S3-015

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-015
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['NIST 800', 'GDPR'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-CFR-S3-015

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-015
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['NIST 800', 'GDPR'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-CFR-S3-015

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-015
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['NIST 800', 'GDPR'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-CFR-S3-015

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-015
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['NIST 800', 'GDPR'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-CFR-S3-015

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-015
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['NIST 800', 'GDPR'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-CFR-S3-015

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT47                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_Bucket_With_Retain_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-S3-015
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['NIST 800', 'GDPR'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-CFR-S3-015

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT48                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::cloudfront::distribution', 'aws::route53::recordset', 'aws::s3::bucket']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-S3-015
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['NIST 800', 'GDPR'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-CFR-S3-015

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
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::iam::role', 'custom::lambdatrig', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-S3-015
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['NIST 800', 'GDPR'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-CFR-S3-015

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
| resourceTypes | ['aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroup', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::kms::key', 'custom::lambdaversion', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::iam::role', 'aws::ec2::instance', 'aws::elasticloadbalancingv2::listenerrule', 'aws::kms::alias', 'aws::elasticloadbalancingv2::listener', 'aws::cloudfront::distribution', 'aws::s3::bucketpolicy', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-S3-015
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['NIST 800', 'GDPR'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-CFR-S3-015

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-S3-015
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['NIST 800', 'GDPR'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-CFR-S3-015

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket', 'aws::ec2::flowlog']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-S3-015
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['NIST 800', 'GDPR'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT6                                                                                                               |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/test_2.yaml'] |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT11                                                                                                                        |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                                            |
| collection    | cloudformationtemplate                                                                                                                         |
| type          | cloudformation                                                                                                                                 |
| region        |                                                                                                                                                |
| resourceTypes | ['aws::s3::bucket']                                                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python_example.yaml'] |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT13                                                                                                                                |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                 |
| type          | cloudformation                                                                                                                                         |
| region        |                                                                                                                                                        |
| resourceTypes | ['aws::s3::bucket']                                                                                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string_example.yaml'] |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

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
| resourceTypes | ['aws::sns::topic', 'aws::s3::bucket', 'aws::config::configurationrecorder', 'aws::config::configrule', 'aws::iam::role', 'aws::lambda::permission', 'aws::ec2::volume', 'aws::sns::topicpolicy', 'aws::config::deliverychannel', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::autoscaling::launchconfiguration'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT47                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_Bucket_With_Retain_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT48                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::cloudfront::distribution', 'aws::route53::recordset', 'aws::s3::bucket']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

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
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::iam::role', 'custom::lambdatrig', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

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
| resourceTypes | ['aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroup', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::kms::key', 'custom::lambdaversion', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::iam::role', 'aws::ec2::instance', 'aws::elasticloadbalancingv2::listenerrule', 'aws::kms::alias', 'aws::elasticloadbalancingv2::listener', 'aws::cloudfront::distribution', 'aws::s3::bucketpolicy', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable ObjectLockEnabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-CFR-S3-016

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket', 'aws::ec2::flowlog']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-S3-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT6                                                                                                               |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/test_2.yaml'] |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT11                                                                                                                        |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                                            |
| collection    | cloudformationtemplate                                                                                                                         |
| type          | cloudformation                                                                                                                                 |
| region        |                                                                                                                                                |
| resourceTypes | ['aws::s3::bucket']                                                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python_example.yaml'] |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT13                                                                                                                                |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                 |
| type          | cloudformation                                                                                                                                         |
| region        |                                                                                                                                                        |
| resourceTypes | ['aws::s3::bucket']                                                                                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string_example.yaml'] |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

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
| resourceTypes | ['aws::sns::topic', 'aws::s3::bucket', 'aws::config::configurationrecorder', 'aws::config::configrule', 'aws::iam::role', 'aws::lambda::permission', 'aws::ec2::volume', 'aws::sns::topicpolicy', 'aws::config::deliverychannel', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::autoscaling::launchconfiguration'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT47                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_Bucket_With_Retain_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT48                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::cloudfront::distribution', 'aws::route53::recordset', 'aws::s3::bucket']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **passed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

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
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::iam::role', 'custom::lambdatrig', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

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
| resourceTypes | ['aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroup', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::kms::key', 'custom::lambdaversion', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::iam::role', 'aws::ec2::instance', 'aws::elasticloadbalancingv2::listenerrule', 'aws::kms::alias', 'aws::elasticloadbalancingv2::listener', 'aws::cloudfront::distribution', 'aws::s3::bucketpolicy', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-CFR-S3-017

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket', 'aws::ec2::flowlog']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-S3-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **failed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT6                                                                                                               |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/test_2.yaml'] |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **failed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT11                                                                                                                        |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                                            |
| collection    | cloudformationtemplate                                                                                                                         |
| type          | cloudformation                                                                                                                                 |
| region        |                                                                                                                                                |
| resourceTypes | ['aws::s3::bucket']                                                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python_example.yaml'] |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **failed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT13                                                                                                                                |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                 |
| type          | cloudformation                                                                                                                                         |
| region        |                                                                                                                                                        |
| resourceTypes | ['aws::s3::bucket']                                                                                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string_example.yaml'] |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **failed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

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
| resourceTypes | ['aws::sns::topic', 'aws::s3::bucket', 'aws::config::configurationrecorder', 'aws::config::configrule', 'aws::iam::role', 'aws::lambda::permission', 'aws::ec2::volume', 'aws::sns::topicpolicy', 'aws::config::deliverychannel', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **failed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **failed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::autoscaling::launchconfiguration'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **failed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **failed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **failed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **failed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **failed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **failed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT47                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_Bucket_With_Retain_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **failed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT48                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::cloudfront::distribution', 'aws::route53::recordset', 'aws::s3::bucket']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **passed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

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
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::iam::role', 'custom::lambdatrig', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **failed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

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
| resourceTypes | ['aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroup', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::kms::key', 'custom::lambdaversion', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::iam::role', 'aws::ec2::instance', 'aws::elasticloadbalancingv2::listenerrule', 'aws::kms::alias', 'aws::elasticloadbalancingv2::listener', 'aws::cloudfront::distribution', 'aws::s3::bucketpolicy', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **passed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-018
Title: Ensure S3 Bucket has public access blocks\
Test Result: **passed**\
Description : We recommend you ensure S3 bucket has public access blocks. If the public access block is not attached it defaults to False\

#### Test Details
- eval: data.rule.s3_public_access_block
- id : PR-AWS-CFR-S3-018

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket', 'aws::ec2::flowlog']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-S3-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **failed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT6                                                                                                               |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/test_2.yaml'] |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **failed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT11                                                                                                                        |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                                            |
| collection    | cloudformationtemplate                                                                                                                         |
| type          | cloudformation                                                                                                                                 |
| region        |                                                                                                                                                |
| resourceTypes | ['aws::s3::bucket']                                                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python_example.yaml'] |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **failed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT13                                                                                                                                |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                 |
| type          | cloudformation                                                                                                                                         |
| region        |                                                                                                                                                        |
| resourceTypes | ['aws::s3::bucket']                                                                                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string_example.yaml'] |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **failed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

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
| resourceTypes | ['aws::sns::topic', 'aws::s3::bucket', 'aws::config::configurationrecorder', 'aws::config::configrule', 'aws::iam::role', 'aws::lambda::permission', 'aws::ec2::volume', 'aws::sns::topicpolicy', 'aws::config::deliverychannel', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **failed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **failed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::autoscaling::launchconfiguration'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **failed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **failed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **failed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **failed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **failed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **failed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT47                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_Bucket_With_Retain_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **failed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT48                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::cloudfront::distribution', 'aws::route53::recordset', 'aws::s3::bucket']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **passed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

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
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::iam::role', 'custom::lambdatrig', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **failed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

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
| resourceTypes | ['aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroup', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::kms::key', 'custom::lambdaversion', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::iam::role', 'aws::ec2::instance', 'aws::elasticloadbalancingv2::listenerrule', 'aws::kms::alias', 'aws::elasticloadbalancingv2::listener', 'aws::cloudfront::distribution', 'aws::s3::bucketpolicy', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **passed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-019
Title: Ensure S3 bucket RestrictPublicBucket is enabled\
Test Result: **passed**\
Description : Enabling this setting does not affect previously stored bucket policies. Public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked\

#### Test Details
- eval: data.rule.s3_restrict_public_bucket
- id : PR-AWS-CFR-S3-019

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket', 'aws::ec2::flowlog']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-S3-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **failed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT6                                                                                                               |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/test_2.yaml'] |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **failed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT11                                                                                                                        |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                                            |
| collection    | cloudformationtemplate                                                                                                                         |
| type          | cloudformation                                                                                                                                 |
| region        |                                                                                                                                                |
| resourceTypes | ['aws::s3::bucket']                                                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python_example.yaml'] |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **failed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT13                                                                                                                                |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                 |
| type          | cloudformation                                                                                                                                         |
| region        |                                                                                                                                                        |
| resourceTypes | ['aws::s3::bucket']                                                                                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string_example.yaml'] |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **failed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

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
| resourceTypes | ['aws::sns::topic', 'aws::s3::bucket', 'aws::config::configurationrecorder', 'aws::config::configrule', 'aws::iam::role', 'aws::lambda::permission', 'aws::ec2::volume', 'aws::sns::topicpolicy', 'aws::config::deliverychannel', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **failed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **failed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::autoscaling::launchconfiguration'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **failed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **failed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **failed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **failed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **failed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **failed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT47                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_Bucket_With_Retain_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **failed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT48                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::cloudfront::distribution', 'aws::route53::recordset', 'aws::s3::bucket']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **passed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

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
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::iam::role', 'custom::lambdatrig', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **failed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

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
| resourceTypes | ['aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroup', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::kms::key', 'custom::lambdaversion', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::iam::role', 'aws::ec2::instance', 'aws::elasticloadbalancingv2::listenerrule', 'aws::kms::alias', 'aws::elasticloadbalancingv2::listener', 'aws::cloudfront::distribution', 'aws::s3::bucketpolicy', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **passed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-020
Title: Ensure S3 bucket IgnorePublicAcls is enabled\
Test Result: **passed**\
Description : This will block public access granted by ACLs while still allowing PUT Object calls that include a public ACL\

#### Test Details
- eval: data.rule.s3_ignore_public_acl
- id : PR-AWS-CFR-S3-020

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket', 'aws::ec2::flowlog']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-S3-020
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **failed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT6                                                                                                               |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/test_2.yaml'] |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **failed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

#### Snapshots
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT11                                                                                                                        |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                                            |
| collection    | cloudformationtemplate                                                                                                                         |
| type          | cloudformation                                                                                                                                 |
| region        |                                                                                                                                                |
| resourceTypes | ['aws::s3::bucket']                                                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python_example.yaml'] |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **failed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT13                                                                                                                                |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                                 |
| type          | cloudformation                                                                                                                                         |
| region        |                                                                                                                                                        |
| resourceTypes | ['aws::s3::bucket']                                                                                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string_example.yaml'] |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **failed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

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
| resourceTypes | ['aws::sns::topic', 'aws::s3::bucket', 'aws::config::configurationrecorder', 'aws::config::configrule', 'aws::iam::role', 'aws::lambda::permission', 'aws::ec2::volume', 'aws::sns::topicpolicy', 'aws::config::deliverychannel', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **failed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **failed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

#### Snapshots
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT30                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                                                                                               |
| collection    | cloudformationtemplate                                                                                                                                                                            |
| type          | cloudformation                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::autoscaling::launchconfiguration'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **failed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT40                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **failed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

#### Snapshots
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT41                                                                                                                       |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                                           |
| collection    | cloudformationtemplate                                                                                                                        |
| type          | cloudformation                                                                                                                                |
| region        |                                                                                                                                               |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **failed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT42                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **failed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT43                                                                                                      |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                          |
| collection    | cloudformationtemplate                                                                                                       |
| type          | cloudformation                                                                                                               |
| region        |                                                                                                                              |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **failed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT44                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **failed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT47                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::s3::bucket']                                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_Bucket_With_Retain_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **failed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT48                                                                                                              |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                                  |
| collection    | cloudformationtemplate                                                                                                               |
| type          | cloudformation                                                                                                                       |
| region        |                                                                                                                                      |
| resourceTypes | ['aws::cloudfront::distribution', 'aws::route53::recordset', 'aws::s3::bucket']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **passed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

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
| resourceTypes | ['aws::kms::key', 'aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::iam::role', 'custom::lambdatrig', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **failed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

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
| resourceTypes | ['aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroup', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::kms::key', 'custom::lambdaversion', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::iam::role', 'aws::ec2::instance', 'aws::elasticloadbalancingv2::listenerrule', 'aws::kms::alias', 'aws::elasticloadbalancingv2::listener', 'aws::cloudfront::distribution', 'aws::s3::bucketpolicy', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **passed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT91                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-S3-021
Title: Ensure S3 Bucket BlockPublicPolicy is enabled\
Test Result: **passed**\
Description : If an AWS account is used to host a data lake or another business application, blocking public access will serve as an account-level guard against accidental public exposure.\

#### Test Details
- eval: data.rule.s3_block_public_policy
- id : PR-AWS-CFR-S3-021

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT98                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::s3::bucketpolicy', 'aws::s3::bucket', 'aws::ec2::flowlog']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-S3-021
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-001
Title: AWS RDS DB cluster encryption is disabled\
Test Result: **failed**\
Description : This policy identifies RDS DB clusters for which encryption is disabled. Amazon Aurora encrypted DB clusters provide an additional layer of data protection by securing your data from unauthorized access to the underlying storage. You can use Amazon Aurora encryption to increase data protection of your applications deployed in the cloud, and to fulfill compliance requirements for data-at-rest encryption._x005F_x000D_ NOTE: This policy is applicable only for Aurora DB clusters._x005F_x000D_ https://docs.aws.amazon.com/cli/latest/reference/rds/describe-db-clusters.html\

#### Test Details
- eval: data.rule.rds_cluster_encrypt
- id : PR-AWS-CFR-RDS-001

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-RDS-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description                                                               |
|:-----------|:--------------------------------------------------------------------------|
| cloud      | git                                                                       |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'PCI-DSS', 'GDPR'] |
| service    | ['cloudformation']                                                        |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-002
Title: AWS RDS database instance is publicly accessible\
Test Result: **failed**\
Description : This policy identifies RDS database instances which are publicly accessible.DB instances should not be publicly accessible to protect the integrety of data.Public accessibility of DB instances can be modified by turning on or off the Public accessibility parameter.\

#### Test Details
- eval: data.rule.rds_public
- id : PR-AWS-CFR-RDS-002

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-RDS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: High

tags
| Title      | Description                                                                 |
|:-----------|:----------------------------------------------------------------------------|
| cloud      | git                                                                         |
| compliance | ['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'PCI-DSS', 'HIPAA', 'GDPR'] |
| service    | ['cloudformation']                                                          |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-002
Title: AWS RDS database instance is publicly accessible\
Test Result: **passed**\
Description : This policy identifies RDS database instances which are publicly accessible.DB instances should not be publicly accessible to protect the integrety of data.Public accessibility of DB instances can be modified by turning on or off the Public accessibility parameter.\

#### Test Details
- eval: data.rule.rds_public
- id : PR-AWS-CFR-RDS-002

#### Snapshots
| Title         | Description                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT36                                                                                                   |
| structure     | filesystem                                                                                                                |
| reference     | master                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                       |
| collection    | cloudformationtemplate                                                                                                    |
| type          | cloudformation                                                                                                            |
| region        |                                                                                                                           |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::rds::dbsecuritygroup', 'aws::rds::dbinstance']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: High

tags
| Title      | Description                                                                 |
|:-----------|:----------------------------------------------------------------------------|
| cloud      | git                                                                         |
| compliance | ['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'PCI-DSS', 'HIPAA', 'GDPR'] |
| service    | ['cloudformation']                                                          |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-002
Title: AWS RDS database instance is publicly accessible\
Test Result: **passed**\
Description : This policy identifies RDS database instances which are publicly accessible.DB instances should not be publicly accessible to protect the integrety of data.Public accessibility of DB instances can be modified by turning on or off the Public accessibility parameter.\

#### Test Details
- eval: data.rule.rds_public
- id : PR-AWS-CFR-RDS-002

#### Snapshots
| Title         | Description                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT37                                                                                 |
| structure     | filesystem                                                                                              |
| reference     | master                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                     |
| collection    | cloudformationtemplate                                                                                  |
| type          | cloudformation                                                                                          |
| region        |                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_PIOPS.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: High

tags
| Title      | Description                                                                 |
|:-----------|:----------------------------------------------------------------------------|
| cloud      | git                                                                         |
| compliance | ['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'PCI-DSS', 'HIPAA', 'GDPR'] |
| service    | ['cloudformation']                                                          |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-002
Title: AWS RDS database instance is publicly accessible\
Test Result: **passed**\
Description : This policy identifies RDS database instances which are publicly accessible.DB instances should not be publicly accessible to protect the integrety of data.Public accessibility of DB instances can be modified by turning on or off the Public accessibility parameter.\

#### Test Details
- eval: data.rule.rds_public
- id : PR-AWS-CFR-RDS-002

#### Snapshots
| Title         | Description                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT38                                                                                              |
| structure     | filesystem                                                                                                           |
| reference     | master                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                  |
| collection    | cloudformationtemplate                                                                                               |
| type          | cloudformation                                                                                                       |
| region        |                                                                                                                      |
| resourceTypes | ['aws::rds::dbinstance']                                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_Snapshot_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: High

tags
| Title      | Description                                                                 |
|:-----------|:----------------------------------------------------------------------------|
| cloud      | git                                                                         |
| compliance | ['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'PCI-DSS', 'HIPAA', 'GDPR'] |
| service    | ['cloudformation']                                                          |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-002
Title: AWS RDS database instance is publicly accessible\
Test Result: **passed**\
Description : This policy identifies RDS database instances which are publicly accessible.DB instances should not be publicly accessible to protect the integrety of data.Public accessibility of DB instances can be modified by turning on or off the Public accessibility parameter.\

#### Test Details
- eval: data.rule.rds_public
- id : PR-AWS-CFR-RDS-002

#### Snapshots
| Title         | Description                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT39                                                                                                 |
| structure     | filesystem                                                                                                              |
| reference     | master                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                     |
| collection    | cloudformationtemplate                                                                                                  |
| type          | cloudformation                                                                                                          |
| region        |                                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbparametergroup']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_with_DBParameterGroup.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: High

tags
| Title      | Description                                                                 |
|:-----------|:----------------------------------------------------------------------------|
| cloud      | git                                                                         |
| compliance | ['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'PCI-DSS', 'HIPAA', 'GDPR'] |
| service    | ['cloudformation']                                                          |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-003
Title: AWS RDS database not encrypted using Customer Managed Key\
Test Result: **failed**\
Description : This policy identifies RDS databases that are encrypted with default KMS keys and not with customer managed keys. As a best practice, use customer managed keys to encrypt the data on your RDS databases and maintain control of your keys and data on sensitive workloads.\

#### Test Details
- eval: data.rule.rds_encrypt_key
- id : PR-AWS-CFR-RDS-003

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-RDS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: High

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['GDPR', 'NIST 800'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-003
Title: AWS RDS database not encrypted using Customer Managed Key\
Test Result: **failed**\
Description : This policy identifies RDS databases that are encrypted with default KMS keys and not with customer managed keys. As a best practice, use customer managed keys to encrypt the data on your RDS databases and maintain control of your keys and data on sensitive workloads.\

#### Test Details
- eval: data.rule.rds_encrypt_key
- id : PR-AWS-CFR-RDS-003

#### Snapshots
| Title         | Description                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT36                                                                                                   |
| structure     | filesystem                                                                                                                |
| reference     | master                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                       |
| collection    | cloudformationtemplate                                                                                                    |
| type          | cloudformation                                                                                                            |
| region        |                                                                                                                           |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::rds::dbsecuritygroup', 'aws::rds::dbinstance']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: High

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['GDPR', 'NIST 800'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-003
Title: AWS RDS database not encrypted using Customer Managed Key\
Test Result: **failed**\
Description : This policy identifies RDS databases that are encrypted with default KMS keys and not with customer managed keys. As a best practice, use customer managed keys to encrypt the data on your RDS databases and maintain control of your keys and data on sensitive workloads.\

#### Test Details
- eval: data.rule.rds_encrypt_key
- id : PR-AWS-CFR-RDS-003

#### Snapshots
| Title         | Description                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT37                                                                                 |
| structure     | filesystem                                                                                              |
| reference     | master                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                     |
| collection    | cloudformationtemplate                                                                                  |
| type          | cloudformation                                                                                          |
| region        |                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_PIOPS.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: High

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['GDPR', 'NIST 800'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-003
Title: AWS RDS database not encrypted using Customer Managed Key\
Test Result: **failed**\
Description : This policy identifies RDS databases that are encrypted with default KMS keys and not with customer managed keys. As a best practice, use customer managed keys to encrypt the data on your RDS databases and maintain control of your keys and data on sensitive workloads.\

#### Test Details
- eval: data.rule.rds_encrypt_key
- id : PR-AWS-CFR-RDS-003

#### Snapshots
| Title         | Description                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT38                                                                                              |
| structure     | filesystem                                                                                                           |
| reference     | master                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                  |
| collection    | cloudformationtemplate                                                                                               |
| type          | cloudformation                                                                                                       |
| region        |                                                                                                                      |
| resourceTypes | ['aws::rds::dbinstance']                                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_Snapshot_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: High

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['GDPR', 'NIST 800'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-003
Title: AWS RDS database not encrypted using Customer Managed Key\
Test Result: **failed**\
Description : This policy identifies RDS databases that are encrypted with default KMS keys and not with customer managed keys. As a best practice, use customer managed keys to encrypt the data on your RDS databases and maintain control of your keys and data on sensitive workloads.\

#### Test Details
- eval: data.rule.rds_encrypt_key
- id : PR-AWS-CFR-RDS-003

#### Snapshots
| Title         | Description                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT39                                                                                                 |
| structure     | filesystem                                                                                                              |
| reference     | master                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                     |
| collection    | cloudformationtemplate                                                                                                  |
| type          | cloudformation                                                                                                          |
| region        |                                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbparametergroup']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_with_DBParameterGroup.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: High

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['GDPR', 'NIST 800'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-006
Title: AWS RDS instance is not encrypted\
Test Result: **failed**\
Description : This policy identifies AWS RDS instances which are not encrypted. Amazon Relational Database Service (Amazon RDS) is a web service that makes it easier to set up and manage databases. Amazon allows customers to turn on encryption for RDS which is recommended for compliance and security reasons.\

#### Test Details
- eval: data.rule.rds_encrypt
- id : PR-AWS-CFR-RDS-006

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-RDS-006
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description                                                                             |
|:-----------|:----------------------------------------------------------------------------------------|
| cloud      | git                                                                                     |
| compliance | ['CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['cloudformation']                                                                      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-006
Title: AWS RDS instance is not encrypted\
Test Result: **failed**\
Description : This policy identifies AWS RDS instances which are not encrypted. Amazon Relational Database Service (Amazon RDS) is a web service that makes it easier to set up and manage databases. Amazon allows customers to turn on encryption for RDS which is recommended for compliance and security reasons.\

#### Test Details
- eval: data.rule.rds_encrypt
- id : PR-AWS-CFR-RDS-006

#### Snapshots
| Title         | Description                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT36                                                                                                   |
| structure     | filesystem                                                                                                                |
| reference     | master                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                       |
| collection    | cloudformationtemplate                                                                                                    |
| type          | cloudformation                                                                                                            |
| region        |                                                                                                                           |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::rds::dbsecuritygroup', 'aws::rds::dbinstance']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-006
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description                                                                             |
|:-----------|:----------------------------------------------------------------------------------------|
| cloud      | git                                                                                     |
| compliance | ['CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['cloudformation']                                                                      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-006
Title: AWS RDS instance is not encrypted\
Test Result: **failed**\
Description : This policy identifies AWS RDS instances which are not encrypted. Amazon Relational Database Service (Amazon RDS) is a web service that makes it easier to set up and manage databases. Amazon allows customers to turn on encryption for RDS which is recommended for compliance and security reasons.\

#### Test Details
- eval: data.rule.rds_encrypt
- id : PR-AWS-CFR-RDS-006

#### Snapshots
| Title         | Description                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT37                                                                                 |
| structure     | filesystem                                                                                              |
| reference     | master                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                     |
| collection    | cloudformationtemplate                                                                                  |
| type          | cloudformation                                                                                          |
| region        |                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_PIOPS.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-006
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description                                                                             |
|:-----------|:----------------------------------------------------------------------------------------|
| cloud      | git                                                                                     |
| compliance | ['CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['cloudformation']                                                                      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-006
Title: AWS RDS instance is not encrypted\
Test Result: **failed**\
Description : This policy identifies AWS RDS instances which are not encrypted. Amazon Relational Database Service (Amazon RDS) is a web service that makes it easier to set up and manage databases. Amazon allows customers to turn on encryption for RDS which is recommended for compliance and security reasons.\

#### Test Details
- eval: data.rule.rds_encrypt
- id : PR-AWS-CFR-RDS-006

#### Snapshots
| Title         | Description                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT38                                                                                              |
| structure     | filesystem                                                                                                           |
| reference     | master                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                  |
| collection    | cloudformationtemplate                                                                                               |
| type          | cloudformation                                                                                                       |
| region        |                                                                                                                      |
| resourceTypes | ['aws::rds::dbinstance']                                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_Snapshot_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-006
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description                                                                             |
|:-----------|:----------------------------------------------------------------------------------------|
| cloud      | git                                                                                     |
| compliance | ['CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['cloudformation']                                                                      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-006
Title: AWS RDS instance is not encrypted\
Test Result: **failed**\
Description : This policy identifies AWS RDS instances which are not encrypted. Amazon Relational Database Service (Amazon RDS) is a web service that makes it easier to set up and manage databases. Amazon allows customers to turn on encryption for RDS which is recommended for compliance and security reasons.\

#### Test Details
- eval: data.rule.rds_encrypt
- id : PR-AWS-CFR-RDS-006

#### Snapshots
| Title         | Description                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT39                                                                                                 |
| structure     | filesystem                                                                                                              |
| reference     | master                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                     |
| collection    | cloudformationtemplate                                                                                                  |
| type          | cloudformation                                                                                                          |
| region        |                                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbparametergroup']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_with_DBParameterGroup.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-006
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description                                                                             |
|:-----------|:----------------------------------------------------------------------------------------|
| cloud      | git                                                                                     |
| compliance | ['CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['cloudformation']                                                                      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-007
Title: AWS RDS instance with Multi-Availability Zone disabled\
Test Result: **passed**\
Description : This policy identifies RDS instances which have Multi-Availability Zone(Multi-AZ) disabled. When RDS DB instance is enabled with Multi-AZ, RDS automatically creates a primary DB Instance and synchronously replicates the data to a standby instance in a different availability zone. These Multi-AZ deployments will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primaryâ€™s availability zone for read/write operations, so by making them the best fit for production database workloads.\

#### Test Details
- eval: data.rule.rds_multiaz
- id : PR-AWS-CFR-RDS-007

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-RDS-007
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-007
Title: AWS RDS instance with Multi-Availability Zone disabled\
Test Result: **failed**\
Description : This policy identifies RDS instances which have Multi-Availability Zone(Multi-AZ) disabled. When RDS DB instance is enabled with Multi-AZ, RDS automatically creates a primary DB Instance and synchronously replicates the data to a standby instance in a different availability zone. These Multi-AZ deployments will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primaryâ€™s availability zone for read/write operations, so by making them the best fit for production database workloads.\

#### Test Details
- eval: data.rule.rds_multiaz
- id : PR-AWS-CFR-RDS-007

#### Snapshots
| Title         | Description                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT36                                                                                                   |
| structure     | filesystem                                                                                                                |
| reference     | master                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                       |
| collection    | cloudformationtemplate                                                                                                    |
| type          | cloudformation                                                                                                            |
| region        |                                                                                                                           |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::rds::dbsecuritygroup', 'aws::rds::dbinstance']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-007
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-007
Title: AWS RDS instance with Multi-Availability Zone disabled\
Test Result: **failed**\
Description : This policy identifies RDS instances which have Multi-Availability Zone(Multi-AZ) disabled. When RDS DB instance is enabled with Multi-AZ, RDS automatically creates a primary DB Instance and synchronously replicates the data to a standby instance in a different availability zone. These Multi-AZ deployments will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primaryâ€™s availability zone for read/write operations, so by making them the best fit for production database workloads.\

#### Test Details
- eval: data.rule.rds_multiaz
- id : PR-AWS-CFR-RDS-007

#### Snapshots
| Title         | Description                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT37                                                                                 |
| structure     | filesystem                                                                                              |
| reference     | master                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                     |
| collection    | cloudformationtemplate                                                                                  |
| type          | cloudformation                                                                                          |
| region        |                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_PIOPS.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-007
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-007
Title: AWS RDS instance with Multi-Availability Zone disabled\
Test Result: **failed**\
Description : This policy identifies RDS instances which have Multi-Availability Zone(Multi-AZ) disabled. When RDS DB instance is enabled with Multi-AZ, RDS automatically creates a primary DB Instance and synchronously replicates the data to a standby instance in a different availability zone. These Multi-AZ deployments will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primaryâ€™s availability zone for read/write operations, so by making them the best fit for production database workloads.\

#### Test Details
- eval: data.rule.rds_multiaz
- id : PR-AWS-CFR-RDS-007

#### Snapshots
| Title         | Description                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT38                                                                                              |
| structure     | filesystem                                                                                                           |
| reference     | master                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                  |
| collection    | cloudformationtemplate                                                                                               |
| type          | cloudformation                                                                                                       |
| region        |                                                                                                                      |
| resourceTypes | ['aws::rds::dbinstance']                                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_Snapshot_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-007
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-007
Title: AWS RDS instance with Multi-Availability Zone disabled\
Test Result: **failed**\
Description : This policy identifies RDS instances which have Multi-Availability Zone(Multi-AZ) disabled. When RDS DB instance is enabled with Multi-AZ, RDS automatically creates a primary DB Instance and synchronously replicates the data to a standby instance in a different availability zone. These Multi-AZ deployments will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primaryâ€™s availability zone for read/write operations, so by making them the best fit for production database workloads.\

#### Test Details
- eval: data.rule.rds_multiaz
- id : PR-AWS-CFR-RDS-007

#### Snapshots
| Title         | Description                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT39                                                                                                 |
| structure     | filesystem                                                                                                              |
| reference     | master                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                     |
| collection    | cloudformationtemplate                                                                                                  |
| type          | cloudformation                                                                                                          |
| region        |                                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbparametergroup']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_with_DBParameterGroup.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-007
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-008
Title: AWS RDS instance with copy tags to snapshots disabled\
Test Result: **failed**\
Description : This policy identifies RDS instances which have copy tags to snapshots disabled. Copy tags to snapshots copies all the user-defined tags from the DB instance to snapshots. Copying tags allow you to add metadata and apply access policies to your Amazon RDS resources.\

#### Test Details
- eval: data.rule.rds_snapshot
- id : PR-AWS-CFR-RDS-008

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-RDS-008
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-008
Title: AWS RDS instance with copy tags to snapshots disabled\
Test Result: **failed**\
Description : This policy identifies RDS instances which have copy tags to snapshots disabled. Copy tags to snapshots copies all the user-defined tags from the DB instance to snapshots. Copying tags allow you to add metadata and apply access policies to your Amazon RDS resources.\

#### Test Details
- eval: data.rule.rds_snapshot
- id : PR-AWS-CFR-RDS-008

#### Snapshots
| Title         | Description                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT36                                                                                                   |
| structure     | filesystem                                                                                                                |
| reference     | master                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                       |
| collection    | cloudformationtemplate                                                                                                    |
| type          | cloudformation                                                                                                            |
| region        |                                                                                                                           |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::rds::dbsecuritygroup', 'aws::rds::dbinstance']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-008
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-008
Title: AWS RDS instance with copy tags to snapshots disabled\
Test Result: **failed**\
Description : This policy identifies RDS instances which have copy tags to snapshots disabled. Copy tags to snapshots copies all the user-defined tags from the DB instance to snapshots. Copying tags allow you to add metadata and apply access policies to your Amazon RDS resources.\

#### Test Details
- eval: data.rule.rds_snapshot
- id : PR-AWS-CFR-RDS-008

#### Snapshots
| Title         | Description                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT37                                                                                 |
| structure     | filesystem                                                                                              |
| reference     | master                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                     |
| collection    | cloudformationtemplate                                                                                  |
| type          | cloudformation                                                                                          |
| region        |                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_PIOPS.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-008
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-008
Title: AWS RDS instance with copy tags to snapshots disabled\
Test Result: **failed**\
Description : This policy identifies RDS instances which have copy tags to snapshots disabled. Copy tags to snapshots copies all the user-defined tags from the DB instance to snapshots. Copying tags allow you to add metadata and apply access policies to your Amazon RDS resources.\

#### Test Details
- eval: data.rule.rds_snapshot
- id : PR-AWS-CFR-RDS-008

#### Snapshots
| Title         | Description                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT38                                                                                              |
| structure     | filesystem                                                                                                           |
| reference     | master                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                  |
| collection    | cloudformationtemplate                                                                                               |
| type          | cloudformation                                                                                                       |
| region        |                                                                                                                      |
| resourceTypes | ['aws::rds::dbinstance']                                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_Snapshot_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-008
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-008
Title: AWS RDS instance with copy tags to snapshots disabled\
Test Result: **failed**\
Description : This policy identifies RDS instances which have copy tags to snapshots disabled. Copy tags to snapshots copies all the user-defined tags from the DB instance to snapshots. Copying tags allow you to add metadata and apply access policies to your Amazon RDS resources.\

#### Test Details
- eval: data.rule.rds_snapshot
- id : PR-AWS-CFR-RDS-008

#### Snapshots
| Title         | Description                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT39                                                                                                 |
| structure     | filesystem                                                                                                              |
| reference     | master                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                     |
| collection    | cloudformationtemplate                                                                                                  |
| type          | cloudformation                                                                                                          |
| region        |                                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbparametergroup']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_with_DBParameterGroup.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-008
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-009
Title: AWS RDS instance without Automatic Backup setting\
Test Result: **failed**\
Description : This policy identifies RDS instances which are not set with the Automatic Backup setting. If Automatic Backup is set, RDS creates a storage volume snapshot of your DB instance, backing up the entire DB instance and not just individual databases which provide for point-in-time recovery. The automatic backup will happen during the specified backup window time and keeps the backups for a limited period of time as defined in the retention period. It is recommended to set Automatic backups for your critical RDS servers that will help in the data restoration process.\

#### Test Details
- eval: data.rule.rds_backup
- id : PR-AWS-CFR-RDS-009

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-RDS-009
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-009
Title: AWS RDS instance without Automatic Backup setting\
Test Result: **failed**\
Description : This policy identifies RDS instances which are not set with the Automatic Backup setting. If Automatic Backup is set, RDS creates a storage volume snapshot of your DB instance, backing up the entire DB instance and not just individual databases which provide for point-in-time recovery. The automatic backup will happen during the specified backup window time and keeps the backups for a limited period of time as defined in the retention period. It is recommended to set Automatic backups for your critical RDS servers that will help in the data restoration process.\

#### Test Details
- eval: data.rule.rds_backup
- id : PR-AWS-CFR-RDS-009

#### Snapshots
| Title         | Description                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT36                                                                                                   |
| structure     | filesystem                                                                                                                |
| reference     | master                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                       |
| collection    | cloudformationtemplate                                                                                                    |
| type          | cloudformation                                                                                                            |
| region        |                                                                                                                           |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::rds::dbsecuritygroup', 'aws::rds::dbinstance']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-009
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-009
Title: AWS RDS instance without Automatic Backup setting\
Test Result: **failed**\
Description : This policy identifies RDS instances which are not set with the Automatic Backup setting. If Automatic Backup is set, RDS creates a storage volume snapshot of your DB instance, backing up the entire DB instance and not just individual databases which provide for point-in-time recovery. The automatic backup will happen during the specified backup window time and keeps the backups for a limited period of time as defined in the retention period. It is recommended to set Automatic backups for your critical RDS servers that will help in the data restoration process.\

#### Test Details
- eval: data.rule.rds_backup
- id : PR-AWS-CFR-RDS-009

#### Snapshots
| Title         | Description                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT37                                                                                 |
| structure     | filesystem                                                                                              |
| reference     | master                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                     |
| collection    | cloudformationtemplate                                                                                  |
| type          | cloudformation                                                                                          |
| region        |                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_PIOPS.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-009
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-009
Title: AWS RDS instance without Automatic Backup setting\
Test Result: **failed**\
Description : This policy identifies RDS instances which are not set with the Automatic Backup setting. If Automatic Backup is set, RDS creates a storage volume snapshot of your DB instance, backing up the entire DB instance and not just individual databases which provide for point-in-time recovery. The automatic backup will happen during the specified backup window time and keeps the backups for a limited period of time as defined in the retention period. It is recommended to set Automatic backups for your critical RDS servers that will help in the data restoration process.\

#### Test Details
- eval: data.rule.rds_backup
- id : PR-AWS-CFR-RDS-009

#### Snapshots
| Title         | Description                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT38                                                                                              |
| structure     | filesystem                                                                                                           |
| reference     | master                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                  |
| collection    | cloudformationtemplate                                                                                               |
| type          | cloudformation                                                                                                       |
| region        |                                                                                                                      |
| resourceTypes | ['aws::rds::dbinstance']                                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_Snapshot_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-009
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-009
Title: AWS RDS instance without Automatic Backup setting\
Test Result: **failed**\
Description : This policy identifies RDS instances which are not set with the Automatic Backup setting. If Automatic Backup is set, RDS creates a storage volume snapshot of your DB instance, backing up the entire DB instance and not just individual databases which provide for point-in-time recovery. The automatic backup will happen during the specified backup window time and keeps the backups for a limited period of time as defined in the retention period. It is recommended to set Automatic backups for your critical RDS servers that will help in the data restoration process.\

#### Test Details
- eval: data.rule.rds_backup
- id : PR-AWS-CFR-RDS-009

#### Snapshots
| Title         | Description                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT39                                                                                                 |
| structure     | filesystem                                                                                                              |
| reference     | master                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                     |
| collection    | cloudformationtemplate                                                                                                  |
| type          | cloudformation                                                                                                          |
| region        |                                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbparametergroup']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_with_DBParameterGroup.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-009
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-010
Title: AWS RDS minor upgrades not enabled\
Test Result: **failed**\
Description : When Amazon Relational Database Service (Amazon RDS) supports a new version of a database engine, you can upgrade your DB instances to the new version. There are two kinds of upgrades: major version upgrades and minor version upgrades. Minor upgrades helps maintain a secure and stable RDS with minimal impact on the application. For this reason, we recommend that your automatic minor upgrade is enabled. Minor version upgrades only occur automatically if a minor upgrade replaces an unsafe version, such as a minor upgrade that contains bug fixes for a previous version.\

#### Test Details
- eval: data.rule.rds_upgrade
- id : PR-AWS-CFR-RDS-010

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-RDS-010
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-010
Title: AWS RDS minor upgrades not enabled\
Test Result: **failed**\
Description : When Amazon Relational Database Service (Amazon RDS) supports a new version of a database engine, you can upgrade your DB instances to the new version. There are two kinds of upgrades: major version upgrades and minor version upgrades. Minor upgrades helps maintain a secure and stable RDS with minimal impact on the application. For this reason, we recommend that your automatic minor upgrade is enabled. Minor version upgrades only occur automatically if a minor upgrade replaces an unsafe version, such as a minor upgrade that contains bug fixes for a previous version.\

#### Test Details
- eval: data.rule.rds_upgrade
- id : PR-AWS-CFR-RDS-010

#### Snapshots
| Title         | Description                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT36                                                                                                   |
| structure     | filesystem                                                                                                                |
| reference     | master                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                       |
| collection    | cloudformationtemplate                                                                                                    |
| type          | cloudformation                                                                                                            |
| region        |                                                                                                                           |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::rds::dbsecuritygroup', 'aws::rds::dbinstance']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-010
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-010
Title: AWS RDS minor upgrades not enabled\
Test Result: **failed**\
Description : When Amazon Relational Database Service (Amazon RDS) supports a new version of a database engine, you can upgrade your DB instances to the new version. There are two kinds of upgrades: major version upgrades and minor version upgrades. Minor upgrades helps maintain a secure and stable RDS with minimal impact on the application. For this reason, we recommend that your automatic minor upgrade is enabled. Minor version upgrades only occur automatically if a minor upgrade replaces an unsafe version, such as a minor upgrade that contains bug fixes for a previous version.\

#### Test Details
- eval: data.rule.rds_upgrade
- id : PR-AWS-CFR-RDS-010

#### Snapshots
| Title         | Description                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT37                                                                                 |
| structure     | filesystem                                                                                              |
| reference     | master                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                     |
| collection    | cloudformationtemplate                                                                                  |
| type          | cloudformation                                                                                          |
| region        |                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_PIOPS.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-010
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-010
Title: AWS RDS minor upgrades not enabled\
Test Result: **failed**\
Description : When Amazon Relational Database Service (Amazon RDS) supports a new version of a database engine, you can upgrade your DB instances to the new version. There are two kinds of upgrades: major version upgrades and minor version upgrades. Minor upgrades helps maintain a secure and stable RDS with minimal impact on the application. For this reason, we recommend that your automatic minor upgrade is enabled. Minor version upgrades only occur automatically if a minor upgrade replaces an unsafe version, such as a minor upgrade that contains bug fixes for a previous version.\

#### Test Details
- eval: data.rule.rds_upgrade
- id : PR-AWS-CFR-RDS-010

#### Snapshots
| Title         | Description                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT38                                                                                              |
| structure     | filesystem                                                                                                           |
| reference     | master                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                  |
| collection    | cloudformationtemplate                                                                                               |
| type          | cloudformation                                                                                                       |
| region        |                                                                                                                      |
| resourceTypes | ['aws::rds::dbinstance']                                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_Snapshot_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-010
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-010
Title: AWS RDS minor upgrades not enabled\
Test Result: **failed**\
Description : When Amazon Relational Database Service (Amazon RDS) supports a new version of a database engine, you can upgrade your DB instances to the new version. There are two kinds of upgrades: major version upgrades and minor version upgrades. Minor upgrades helps maintain a secure and stable RDS with minimal impact on the application. For this reason, we recommend that your automatic minor upgrade is enabled. Minor version upgrades only occur automatically if a minor upgrade replaces an unsafe version, such as a minor upgrade that contains bug fixes for a previous version.\

#### Test Details
- eval: data.rule.rds_upgrade
- id : PR-AWS-CFR-RDS-010

#### Snapshots
| Title         | Description                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT39                                                                                                 |
| structure     | filesystem                                                                                                              |
| reference     | master                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                     |
| collection    | cloudformationtemplate                                                                                                  |
| type          | cloudformation                                                                                                          |
| region        |                                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbparametergroup']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_with_DBParameterGroup.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-010
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-011
Title: AWS RDS retention policy less than 7 days\
Test Result: **failed**\
Description : RDS Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).\

#### Test Details
- eval: data.rule.rds_retention
- id : PR-AWS-CFR-RDS-011

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-RDS-011
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-011
Title: AWS RDS retention policy less than 7 days\
Test Result: **failed**\
Description : RDS Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).\

#### Test Details
- eval: data.rule.rds_retention
- id : PR-AWS-CFR-RDS-011

#### Snapshots
| Title         | Description                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT36                                                                                                   |
| structure     | filesystem                                                                                                                |
| reference     | master                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                       |
| collection    | cloudformationtemplate                                                                                                    |
| type          | cloudformation                                                                                                            |
| region        |                                                                                                                           |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::rds::dbsecuritygroup', 'aws::rds::dbinstance']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-011
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-011
Title: AWS RDS retention policy less than 7 days\
Test Result: **failed**\
Description : RDS Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).\

#### Test Details
- eval: data.rule.rds_retention
- id : PR-AWS-CFR-RDS-011

#### Snapshots
| Title         | Description                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT37                                                                                 |
| structure     | filesystem                                                                                              |
| reference     | master                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                     |
| collection    | cloudformationtemplate                                                                                  |
| type          | cloudformation                                                                                          |
| region        |                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_PIOPS.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-011
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-011
Title: AWS RDS retention policy less than 7 days\
Test Result: **failed**\
Description : RDS Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).\

#### Test Details
- eval: data.rule.rds_retention
- id : PR-AWS-CFR-RDS-011

#### Snapshots
| Title         | Description                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT38                                                                                              |
| structure     | filesystem                                                                                                           |
| reference     | master                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                  |
| collection    | cloudformationtemplate                                                                                               |
| type          | cloudformation                                                                                                       |
| region        |                                                                                                                      |
| resourceTypes | ['aws::rds::dbinstance']                                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_Snapshot_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-011
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-011
Title: AWS RDS retention policy less than 7 days\
Test Result: **failed**\
Description : RDS Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).\

#### Test Details
- eval: data.rule.rds_retention
- id : PR-AWS-CFR-RDS-011

#### Snapshots
| Title         | Description                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT39                                                                                                 |
| structure     | filesystem                                                                                                              |
| reference     | master                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                     |
| collection    | cloudformationtemplate                                                                                                  |
| type          | cloudformation                                                                                                          |
| region        |                                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbparametergroup']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_with_DBParameterGroup.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-011
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-012
Title: AWS RDS cluster retention policy less than 7 days\
Test Result: **failed**\
Description : RDS cluster Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).\

#### Test Details
- eval: data.rule.rds_cluster_retention
- id : PR-AWS-CFR-RDS-012

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-RDS-012
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-013
Title: Ensure RDS clusters and instances have deletion protection enabled\
Test Result: **failed**\
Description : This rule Checks if an Amazon Relational Database Service (Amazon RDS) cluster has deletion protection enabled\

#### Test Details
- eval: data.rule.rds_cluster_deletion_protection
- id : PR-AWS-CFR-RDS-013

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-RDS-013
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-016
Title: Ensure RDS cluster has IAM authentication enabled\
Test Result: **failed**\
Description : Ensure IAM Database Authentication feature is enabled in order to use AWS Identity and Access Management (IAM) service to manage database access to your Amazon RDS MySQL and PostgreSQL instances. With this feature enabled, you don't have to use a password when you connect to your MySQL/PostgreSQL database instances, instead you use an authentication token\

#### Test Details
- eval: data.rule.cluster_iam_authenticate
- id : PR-AWS-CFR-RDS-016

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-RDS-016
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-017
Title: Ensure RDS instace has IAM authentication enabled\
Test Result: **failed**\
Description : Ensure IAM Database Authentication feature is enabled in order to use AWS Identity and Access Management (IAM) service to manage database access to your Amazon RDS MySQL and PostgreSQL instances. With this feature enabled, you don't have to use a password when you connect to your MySQL/PostgreSQL database instances, instead you use an authentication token\

#### Test Details
- eval: data.rule.db_instance_iam_authenticate
- id : PR-AWS-CFR-RDS-017

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-RDS-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-017
Title: Ensure RDS instace has IAM authentication enabled\
Test Result: **failed**\
Description : Ensure IAM Database Authentication feature is enabled in order to use AWS Identity and Access Management (IAM) service to manage database access to your Amazon RDS MySQL and PostgreSQL instances. With this feature enabled, you don't have to use a password when you connect to your MySQL/PostgreSQL database instances, instead you use an authentication token\

#### Test Details
- eval: data.rule.db_instance_iam_authenticate
- id : PR-AWS-CFR-RDS-017

#### Snapshots
| Title         | Description                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT36                                                                                                   |
| structure     | filesystem                                                                                                                |
| reference     | master                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                       |
| collection    | cloudformationtemplate                                                                                                    |
| type          | cloudformation                                                                                                            |
| region        |                                                                                                                           |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::rds::dbsecuritygroup', 'aws::rds::dbinstance']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-017
Title: Ensure RDS instace has IAM authentication enabled\
Test Result: **failed**\
Description : Ensure IAM Database Authentication feature is enabled in order to use AWS Identity and Access Management (IAM) service to manage database access to your Amazon RDS MySQL and PostgreSQL instances. With this feature enabled, you don't have to use a password when you connect to your MySQL/PostgreSQL database instances, instead you use an authentication token\

#### Test Details
- eval: data.rule.db_instance_iam_authenticate
- id : PR-AWS-CFR-RDS-017

#### Snapshots
| Title         | Description                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT37                                                                                 |
| structure     | filesystem                                                                                              |
| reference     | master                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                     |
| collection    | cloudformationtemplate                                                                                  |
| type          | cloudformation                                                                                          |
| region        |                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_PIOPS.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-017
Title: Ensure RDS instace has IAM authentication enabled\
Test Result: **failed**\
Description : Ensure IAM Database Authentication feature is enabled in order to use AWS Identity and Access Management (IAM) service to manage database access to your Amazon RDS MySQL and PostgreSQL instances. With this feature enabled, you don't have to use a password when you connect to your MySQL/PostgreSQL database instances, instead you use an authentication token\

#### Test Details
- eval: data.rule.db_instance_iam_authenticate
- id : PR-AWS-CFR-RDS-017

#### Snapshots
| Title         | Description                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT38                                                                                              |
| structure     | filesystem                                                                                                           |
| reference     | master                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                  |
| collection    | cloudformationtemplate                                                                                               |
| type          | cloudformation                                                                                                       |
| region        |                                                                                                                      |
| resourceTypes | ['aws::rds::dbinstance']                                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_Snapshot_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-017
Title: Ensure RDS instace has IAM authentication enabled\
Test Result: **failed**\
Description : Ensure IAM Database Authentication feature is enabled in order to use AWS Identity and Access Management (IAM) service to manage database access to your Amazon RDS MySQL and PostgreSQL instances. With this feature enabled, you don't have to use a password when you connect to your MySQL/PostgreSQL database instances, instead you use an authentication token\

#### Test Details
- eval: data.rule.db_instance_iam_authenticate
- id : PR-AWS-CFR-RDS-017

#### Snapshots
| Title         | Description                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT39                                                                                                 |
| structure     | filesystem                                                                                                              |
| reference     | master                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                     |
| collection    | cloudformationtemplate                                                                                                  |
| type          | cloudformation                                                                                                          |
| region        |                                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbparametergroup']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_with_DBParameterGroup.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-017
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-018
Title: Ensure respective logs of Amazon RDS instance are enabled\
Test Result: **failed**\
Description : Use CloudWatch logging types for Amazon Relational Database Service (Amazon RDS) instances\

#### Test Details
- eval: data.rule.db_instance_cloudwatch_logs
- id : PR-AWS-CFR-RDS-018

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-RDS-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-018
Title: Ensure respective logs of Amazon RDS instance are enabled\
Test Result: **failed**\
Description : Use CloudWatch logging types for Amazon Relational Database Service (Amazon RDS) instances\

#### Test Details
- eval: data.rule.db_instance_cloudwatch_logs
- id : PR-AWS-CFR-RDS-018

#### Snapshots
| Title         | Description                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT36                                                                                                   |
| structure     | filesystem                                                                                                                |
| reference     | master                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                       |
| collection    | cloudformationtemplate                                                                                                    |
| type          | cloudformation                                                                                                            |
| region        |                                                                                                                           |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::rds::dbsecuritygroup', 'aws::rds::dbinstance']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-018
Title: Ensure respective logs of Amazon RDS instance are enabled\
Test Result: **failed**\
Description : Use CloudWatch logging types for Amazon Relational Database Service (Amazon RDS) instances\

#### Test Details
- eval: data.rule.db_instance_cloudwatch_logs
- id : PR-AWS-CFR-RDS-018

#### Snapshots
| Title         | Description                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT37                                                                                 |
| structure     | filesystem                                                                                              |
| reference     | master                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                     |
| collection    | cloudformationtemplate                                                                                  |
| type          | cloudformation                                                                                          |
| region        |                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_PIOPS.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-018
Title: Ensure respective logs of Amazon RDS instance are enabled\
Test Result: **failed**\
Description : Use CloudWatch logging types for Amazon Relational Database Service (Amazon RDS) instances\

#### Test Details
- eval: data.rule.db_instance_cloudwatch_logs
- id : PR-AWS-CFR-RDS-018

#### Snapshots
| Title         | Description                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT38                                                                                              |
| structure     | filesystem                                                                                                           |
| reference     | master                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                  |
| collection    | cloudformationtemplate                                                                                               |
| type          | cloudformation                                                                                                       |
| region        |                                                                                                                      |
| resourceTypes | ['aws::rds::dbinstance']                                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_Snapshot_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-018
Title: Ensure respective logs of Amazon RDS instance are enabled\
Test Result: **failed**\
Description : Use CloudWatch logging types for Amazon Relational Database Service (Amazon RDS) instances\

#### Test Details
- eval: data.rule.db_instance_cloudwatch_logs
- id : PR-AWS-CFR-RDS-018

#### Snapshots
| Title         | Description                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT39                                                                                                 |
| structure     | filesystem                                                                                                              |
| reference     | master                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                     |
| collection    | cloudformationtemplate                                                                                                  |
| type          | cloudformation                                                                                                          |
| region        |                                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbparametergroup']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_with_DBParameterGroup.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-018
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-019
Title: Enhanced monitoring for Amazon RDS instances is enabled\
Test Result: **failed**\
Description : This New Relic integration allows you to monitor and alert on RDS Enhanced Monitoring. You can use integration data and alerts to monitor the DB processes and identify potential trouble spots as well as to profile the DB allowing you to improve and optimize their response and cost\

#### Test Details
- eval: data.rule.db_instance_monitor
- id : PR-AWS-CFR-RDS-019

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::dms::replicationtask', 'aws::dms::replicationsubnetgroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnet', 'aws::iam::role', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::rds::dbinstance', 'aws::dms::replicationinstance', 'aws::rds::dbcluster', 'aws::dms::endpoint', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::rds::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-RDS-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description                                                                         |
|:-----------|:------------------------------------------------------------------------------------|
| cloud      | git                                                                                 |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-019
Title: Enhanced monitoring for Amazon RDS instances is enabled\
Test Result: **failed**\
Description : This New Relic integration allows you to monitor and alert on RDS Enhanced Monitoring. You can use integration data and alerts to monitor the DB processes and identify potential trouble spots as well as to profile the DB allowing you to improve and optimize their response and cost\

#### Test Details
- eval: data.rule.db_instance_monitor
- id : PR-AWS-CFR-RDS-019

#### Snapshots
| Title         | Description                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT36                                                                                                   |
| structure     | filesystem                                                                                                                |
| reference     | master                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                       |
| collection    | cloudformationtemplate                                                                                                    |
| type          | cloudformation                                                                                                            |
| region        |                                                                                                                           |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::rds::dbsecuritygroup', 'aws::rds::dbinstance']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description                                                                         |
|:-----------|:------------------------------------------------------------------------------------|
| cloud      | git                                                                                 |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-019
Title: Enhanced monitoring for Amazon RDS instances is enabled\
Test Result: **failed**\
Description : This New Relic integration allows you to monitor and alert on RDS Enhanced Monitoring. You can use integration data and alerts to monitor the DB processes and identify potential trouble spots as well as to profile the DB allowing you to improve and optimize their response and cost\

#### Test Details
- eval: data.rule.db_instance_monitor
- id : PR-AWS-CFR-RDS-019

#### Snapshots
| Title         | Description                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT37                                                                                 |
| structure     | filesystem                                                                                              |
| reference     | master                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                     |
| collection    | cloudformationtemplate                                                                                  |
| type          | cloudformation                                                                                          |
| region        |                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_PIOPS.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description                                                                         |
|:-----------|:------------------------------------------------------------------------------------|
| cloud      | git                                                                                 |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-019
Title: Enhanced monitoring for Amazon RDS instances is enabled\
Test Result: **failed**\
Description : This New Relic integration allows you to monitor and alert on RDS Enhanced Monitoring. You can use integration data and alerts to monitor the DB processes and identify potential trouble spots as well as to profile the DB allowing you to improve and optimize their response and cost\

#### Test Details
- eval: data.rule.db_instance_monitor
- id : PR-AWS-CFR-RDS-019

#### Snapshots
| Title         | Description                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT38                                                                                              |
| structure     | filesystem                                                                                                           |
| reference     | master                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                  |
| collection    | cloudformationtemplate                                                                                               |
| type          | cloudformation                                                                                                       |
| region        |                                                                                                                      |
| resourceTypes | ['aws::rds::dbinstance']                                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_Snapshot_On_Delete.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description                                                                         |
|:-----------|:------------------------------------------------------------------------------------|
| cloud      | git                                                                                 |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-RDS-019
Title: Enhanced monitoring for Amazon RDS instances is enabled\
Test Result: **failed**\
Description : This New Relic integration allows you to monitor and alert on RDS Enhanced Monitoring. You can use integration data and alerts to monitor the DB processes and identify potential trouble spots as well as to profile the DB allowing you to improve and optimize their response and cost\

#### Test Details
- eval: data.rule.db_instance_monitor
- id : PR-AWS-CFR-RDS-019

#### Snapshots
| Title         | Description                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT39                                                                                                 |
| structure     | filesystem                                                                                                              |
| reference     | master                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                     |
| collection    | cloudformationtemplate                                                                                                  |
| type          | cloudformation                                                                                                          |
| region        |                                                                                                                         |
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbparametergroup']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_with_DBParameterGroup.yaml'] |

- masterTestId: PR-AWS-CFR-RDS-019
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego)
- severity: Medium

tags
| Title      | Description                                                                         |
|:-----------|:------------------------------------------------------------------------------------|
| cloud      | git                                                                                 |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                                  |
----------------------------------------------------------------

