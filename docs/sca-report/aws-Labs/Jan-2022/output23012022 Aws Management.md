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

## Aws Management Services

Source Repository: https://github.com/awslabs/aws-cloudformation-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac

## Compliance run Meta Data
| Title     | Description         |
|:----------|:--------------------|
| timestamp | 1642969803404       |
| snapshot  | master-snapshot_gen |
| container | scenario-aws-Labs   |
| test      | master-test.json    |

## Results

### Test ID - PR-AWS-CFR-SQS-001
Title: AWS SQS does not have a dead letter queue configured\
Test Result: **failed**\
Description : This policy identifies AWS Simple Queue Services (SQS) which does not have dead letter queue configured. Dead letter queues are useful for debugging your application or messaging system because they let you isolate problematic messages to determine why their processing doesn't succeed.\

#### Test Details
- eval: data.rule.sqs_deadletter
- id : PR-AWS-CFR-SQS-001

#### Snapshots
| Title         | Description                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT52                                                                                    |
| structure     | filesystem                                                                                                 |
| reference     | master                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                        |
| collection    | cloudformationtemplate                                                                                     |
| type          | cloudformation                                                                                             |
| region        |                                                                                                            |
| resourceTypes | ['aws::sqs::queue']                                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/SQS/SQSFIFOQueue.json'] |

- masterTestId: PR-AWS-CFR-SQS-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sqs.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SQS-001
Title: AWS SQS does not have a dead letter queue configured\
Test Result: **failed**\
Description : This policy identifies AWS Simple Queue Services (SQS) which does not have dead letter queue configured. Dead letter queues are useful for debugging your application or messaging system because they let you isolate problematic messages to determine why their processing doesn't succeed.\

#### Test Details
- eval: data.rule.sqs_deadletter
- id : PR-AWS-CFR-SQS-001

#### Snapshots
| Title         | Description                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT53                                                                                        |
| structure     | filesystem                                                                                                     |
| reference     | master                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                            |
| collection    | cloudformationtemplate                                                                                         |
| type          | cloudformation                                                                                                 |
| region        |                                                                                                                |
| resourceTypes | ['aws::sqs::queue']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/SQS/SQSStandardQueue.json'] |

- masterTestId: PR-AWS-CFR-SQS-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sqs.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SQS-001
Title: AWS SQS does not have a dead letter queue configured\
Test Result: **failed**\
Description : This policy identifies AWS Simple Queue Services (SQS) which does not have dead letter queue configured. Dead letter queues are useful for debugging your application or messaging system because they let you isolate problematic messages to determine why their processing doesn't succeed.\

#### Test Details
- eval: data.rule.sqs_deadletter
- id : PR-AWS-CFR-SQS-001

#### Snapshots
| Title         | Description                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT94                                                                                                           |
| structure     | filesystem                                                                                                                        |
| reference     | master                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                               |
| collection    | cloudformationtemplate                                                                                                            |
| type          | cloudformation                                                                                                                    |
| region        |                                                                                                                                   |
| resourceTypes | ['aws::sqs::queue', 'aws::dynamodb::table']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/TestResources/events.yaml'] |

- masterTestId: PR-AWS-CFR-SQS-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sqs.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SQS-002
Title: AWS SQS queue encryption using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.\

#### Test Details
- eval: data.rule.sqs_encrypt_key
- id : PR-AWS-CFR-SQS-002

#### Snapshots
| Title         | Description                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT52                                                                                    |
| structure     | filesystem                                                                                                 |
| reference     | master                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                        |
| collection    | cloudformationtemplate                                                                                     |
| type          | cloudformation                                                                                             |
| region        |                                                                                                            |
| resourceTypes | ['aws::sqs::queue']                                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/SQS/SQSFIFOQueue.json'] |

- masterTestId: PR-AWS-CFR-SQS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sqs.rego)
- severity: High

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['GDPR', 'NIST 800'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SQS-002
Title: AWS SQS queue encryption using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.\

#### Test Details
- eval: data.rule.sqs_encrypt_key
- id : PR-AWS-CFR-SQS-002

#### Snapshots
| Title         | Description                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT53                                                                                        |
| structure     | filesystem                                                                                                     |
| reference     | master                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                            |
| collection    | cloudformationtemplate                                                                                         |
| type          | cloudformation                                                                                                 |
| region        |                                                                                                                |
| resourceTypes | ['aws::sqs::queue']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/SQS/SQSStandardQueue.json'] |

- masterTestId: PR-AWS-CFR-SQS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sqs.rego)
- severity: High

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['GDPR', 'NIST 800'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SQS-002
Title: AWS SQS queue encryption using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.\

#### Test Details
- eval: data.rule.sqs_encrypt_key
- id : PR-AWS-CFR-SQS-002

#### Snapshots
| Title         | Description                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT94                                                                                                           |
| structure     | filesystem                                                                                                                        |
| reference     | master                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                               |
| collection    | cloudformationtemplate                                                                                                            |
| type          | cloudformation                                                                                                                    |
| region        |                                                                                                                                   |
| resourceTypes | ['aws::sqs::queue', 'aws::dynamodb::table']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/TestResources/events.yaml'] |

- masterTestId: PR-AWS-CFR-SQS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sqs.rego)
- severity: High

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['GDPR', 'NIST 800'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SQS-003
Title: AWS SQS server side encryption not enabled\
Test Result: **failed**\
Description : SSE lets you transmit sensitive data in encrypted queues. SSE protects the contents of messages in Amazon SQS queues using keys managed in the AWS Key Management Service (AWS KMS). SSE encrypts messages as soon as Amazon SQS receives them. The messages are stored in encrypted form and Amazon SQS decrypts messages only when they are sent to an authorized consumer._x005F_x000D_ _x005F_x000D_ SQS SSE and the AWS KMS security standards can help you meet encryption-related compliance requirements.\

#### Test Details
- eval: data.rule.sqs_encrypt
- id : PR-AWS-CFR-SQS-003

#### Snapshots
| Title         | Description                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT52                                                                                    |
| structure     | filesystem                                                                                                 |
| reference     | master                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                        |
| collection    | cloudformationtemplate                                                                                     |
| type          | cloudformation                                                                                             |
| region        |                                                                                                            |
| resourceTypes | ['aws::sqs::queue']                                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/SQS/SQSFIFOQueue.json'] |

- masterTestId: PR-AWS-CFR-SQS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sqs.rego)
- severity: High

tags
| Title      | Description                              |
|:-----------|:-----------------------------------------|
| cloud      | git                                      |
| compliance | ['HIPAA', 'PCI-DSS', 'NIST 800', 'GDPR'] |
| service    | ['cloudformation']                       |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SQS-003
Title: AWS SQS server side encryption not enabled\
Test Result: **failed**\
Description : SSE lets you transmit sensitive data in encrypted queues. SSE protects the contents of messages in Amazon SQS queues using keys managed in the AWS Key Management Service (AWS KMS). SSE encrypts messages as soon as Amazon SQS receives them. The messages are stored in encrypted form and Amazon SQS decrypts messages only when they are sent to an authorized consumer._x005F_x000D_ _x005F_x000D_ SQS SSE and the AWS KMS security standards can help you meet encryption-related compliance requirements.\

#### Test Details
- eval: data.rule.sqs_encrypt
- id : PR-AWS-CFR-SQS-003

#### Snapshots
| Title         | Description                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT53                                                                                        |
| structure     | filesystem                                                                                                     |
| reference     | master                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                            |
| collection    | cloudformationtemplate                                                                                         |
| type          | cloudformation                                                                                                 |
| region        |                                                                                                                |
| resourceTypes | ['aws::sqs::queue']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/SQS/SQSStandardQueue.json'] |

- masterTestId: PR-AWS-CFR-SQS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sqs.rego)
- severity: High

tags
| Title      | Description                              |
|:-----------|:-----------------------------------------|
| cloud      | git                                      |
| compliance | ['HIPAA', 'PCI-DSS', 'NIST 800', 'GDPR'] |
| service    | ['cloudformation']                       |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SQS-003
Title: AWS SQS server side encryption not enabled\
Test Result: **failed**\
Description : SSE lets you transmit sensitive data in encrypted queues. SSE protects the contents of messages in Amazon SQS queues using keys managed in the AWS Key Management Service (AWS KMS). SSE encrypts messages as soon as Amazon SQS receives them. The messages are stored in encrypted form and Amazon SQS decrypts messages only when they are sent to an authorized consumer._x005F_x000D_ _x005F_x000D_ SQS SSE and the AWS KMS security standards can help you meet encryption-related compliance requirements.\

#### Test Details
- eval: data.rule.sqs_encrypt
- id : PR-AWS-CFR-SQS-003

#### Snapshots
| Title         | Description                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT94                                                                                                           |
| structure     | filesystem                                                                                                                        |
| reference     | master                                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                                               |
| collection    | cloudformationtemplate                                                                                                            |
| type          | cloudformation                                                                                                                    |
| region        |                                                                                                                                   |
| resourceTypes | ['aws::sqs::queue', 'aws::dynamodb::table']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/TestResources/events.yaml'] |

- masterTestId: PR-AWS-CFR-SQS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sqs.rego)
- severity: High

tags
| Title      | Description                              |
|:-----------|:-----------------------------------------|
| cloud      | git                                      |
| compliance | ['HIPAA', 'PCI-DSS', 'NIST 800', 'GDPR'] |
| service    | ['cloudformation']                       |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SNS-001
Title: AWS SNS subscription is not configured with HTTPS\
Test Result: **passed**\
Description : This policy identifies SNS subscriptions using HTTP instead of HTTPS as the delivery protocol in order to enforce SSL encryption for all subscription requests. It is strongly recommended use only HTTPS-based subscriptions by implementing secure SNS topic policies.\

#### Test Details
- eval: data.rule.sns_protocol
- id : PR-AWS-CFR-SNS-001

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::neptune::dbparametergroup', 'aws::sns::topic', 'aws::neptune::dbcluster', 'aws::neptune::dbclusterparametergroup', 'aws::iam::managedpolicy', 'aws::cloudwatch::alarm', 'aws::neptune::dbinstance', 'aws::sns::subscription', 'aws::iam::role', 'aws::neptune::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-SNS-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SNS-001
Title: AWS SNS subscription is not configured with HTTPS\
Test Result: **passed**\
Description : This policy identifies SNS subscriptions using HTTP instead of HTTPS as the delivery protocol in order to enforce SSL encryption for all subscription requests. It is strongly recommended use only HTTPS-based subscriptions by implementing secure SNS topic policies.\

#### Test Details
- eval: data.rule.sns_protocol
- id : PR-AWS-CFR-SNS-001

#### Snapshots
| Title         | Description                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT51                                                                                |
| structure     | filesystem                                                                                             |
| reference     | master                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                    |
| collection    | cloudformationtemplate                                                                                 |
| type          | cloudformation                                                                                         |
| region        |                                                                                                        |
| resourceTypes | ['aws::sns::subscription', 'aws::sns::topic']                                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/SNS/SNSTopic.json'] |

- masterTestId: PR-AWS-CFR-SNS-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SNS-002
Title: AWS SNS topic encrypted using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.\

#### Test Details
- eval: data.rule.sns_encrypt_key
- id : PR-AWS-CFR-SNS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT1                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                   |
| collection    | cloudformationtemplate                                                                                                                                                                                                                |
| type          | cloudformation                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::sns::topic', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::scalingpolicy', 'aws::cloudwatch::alarm', 'aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::autoscalinggroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

- masterTestId: PR-AWS-CFR-SNS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: High

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['GDPR', 'NIST 800'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SNS-002
Title: AWS SNS topic encrypted using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.\

#### Test Details
- eval: data.rule.sns_encrypt_key
- id : PR-AWS-CFR-SNS-002

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
| resourceTypes | ['aws::sns::topic', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::ec2::volume', 'aws::config::configurationrecorder', 'aws::config::configrule', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::lambda::permission', 'aws::iam::role'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-SNS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: High

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['GDPR', 'NIST 800'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SNS-002
Title: AWS SNS topic encrypted using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.\

#### Test Details
- eval: data.rule.sns_encrypt_key
- id : PR-AWS-CFR-SNS-002

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::neptune::dbparametergroup', 'aws::sns::topic', 'aws::neptune::dbcluster', 'aws::neptune::dbclusterparametergroup', 'aws::iam::managedpolicy', 'aws::cloudwatch::alarm', 'aws::neptune::dbinstance', 'aws::sns::subscription', 'aws::iam::role', 'aws::neptune::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-SNS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: High

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['GDPR', 'NIST 800'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SNS-002
Title: AWS SNS topic encrypted using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.\

#### Test Details
- eval: data.rule.sns_encrypt_key
- id : PR-AWS-CFR-SNS-002

#### Snapshots
| Title         | Description                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT51                                                                                |
| structure     | filesystem                                                                                             |
| reference     | master                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                    |
| collection    | cloudformationtemplate                                                                                 |
| type          | cloudformation                                                                                         |
| region        |                                                                                                        |
| resourceTypes | ['aws::sns::subscription', 'aws::sns::topic']                                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/SNS/SNSTopic.json'] |

- masterTestId: PR-AWS-CFR-SNS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: High

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['GDPR', 'NIST 800'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SNS-002
Title: AWS SNS topic encrypted using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.\

#### Test Details
- eval: data.rule.sns_encrypt_key
- id : PR-AWS-CFR-SNS-002

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
| resourceTypes | ['aws::sns::topic', 'aws::logs::loggroup', 'aws::lambda::function', 'aws::iam::role', 'custom::directorysettingsresource']                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/DirectoryServiceSettings/templates/DIRECTORY_SETTINGS.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-SNS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: High

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['GDPR', 'NIST 800'] |
| service    | ['cloudformation']   |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SNS-003
Title: AWS SNS topic with server-side encryption disabled\
Test Result: **failed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.\

#### Test Details
- eval: data.rule.sns_encrypt
- id : PR-AWS-CFR-SNS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT1                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                   |
| collection    | cloudformationtemplate                                                                                                                                                                                                                |
| type          | cloudformation                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::sns::topic', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::scalingpolicy', 'aws::cloudwatch::alarm', 'aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::autoscalinggroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

- masterTestId: PR-AWS-CFR-SNS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: High

tags
| Title      | Description                              |
|:-----------|:-----------------------------------------|
| cloud      | git                                      |
| compliance | ['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800'] |
| service    | ['cloudformation']                       |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SNS-003
Title: AWS SNS topic with server-side encryption disabled\
Test Result: **failed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.\

#### Test Details
- eval: data.rule.sns_encrypt
- id : PR-AWS-CFR-SNS-003

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
| resourceTypes | ['aws::sns::topic', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::ec2::volume', 'aws::config::configurationrecorder', 'aws::config::configrule', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::lambda::permission', 'aws::iam::role'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-SNS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: High

tags
| Title      | Description                              |
|:-----------|:-----------------------------------------|
| cloud      | git                                      |
| compliance | ['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800'] |
| service    | ['cloudformation']                       |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SNS-003
Title: AWS SNS topic with server-side encryption disabled\
Test Result: **failed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.\

#### Test Details
- eval: data.rule.sns_encrypt
- id : PR-AWS-CFR-SNS-003

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::neptune::dbparametergroup', 'aws::sns::topic', 'aws::neptune::dbcluster', 'aws::neptune::dbclusterparametergroup', 'aws::iam::managedpolicy', 'aws::cloudwatch::alarm', 'aws::neptune::dbinstance', 'aws::sns::subscription', 'aws::iam::role', 'aws::neptune::dbsubnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-SNS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: High

tags
| Title      | Description                              |
|:-----------|:-----------------------------------------|
| cloud      | git                                      |
| compliance | ['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800'] |
| service    | ['cloudformation']                       |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SNS-003
Title: AWS SNS topic with server-side encryption disabled\
Test Result: **failed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.\

#### Test Details
- eval: data.rule.sns_encrypt
- id : PR-AWS-CFR-SNS-003

#### Snapshots
| Title         | Description                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT51                                                                                |
| structure     | filesystem                                                                                             |
| reference     | master                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                    |
| collection    | cloudformationtemplate                                                                                 |
| type          | cloudformation                                                                                         |
| region        |                                                                                                        |
| resourceTypes | ['aws::sns::subscription', 'aws::sns::topic']                                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/SNS/SNSTopic.json'] |

- masterTestId: PR-AWS-CFR-SNS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: High

tags
| Title      | Description                              |
|:-----------|:-----------------------------------------|
| cloud      | git                                      |
| compliance | ['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800'] |
| service    | ['cloudformation']                       |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SNS-003
Title: AWS SNS topic with server-side encryption disabled\
Test Result: **passed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.\

#### Test Details
- eval: data.rule.sns_encrypt
- id : PR-AWS-CFR-SNS-003

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
| resourceTypes | ['aws::sns::topic', 'aws::logs::loggroup', 'aws::lambda::function', 'aws::iam::role', 'custom::directorysettingsresource']                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/DirectoryServiceSettings/templates/DIRECTORY_SETTINGS.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-SNS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: High

tags
| Title      | Description                              |
|:-----------|:-----------------------------------------|
| cloud      | git                                      |
| compliance | ['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800'] |
| service    | ['cloudformation']                       |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SNS-004
Title: Ensure SNS Topic policy is not publicly accessible\
Test Result: **passed**\
Description : Public SNS Topic potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.\

#### Test Details
- eval: data.rule.sns_policy_public
- id : PR-AWS-CFR-SNS-004

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
| resourceTypes | ['aws::sns::topic', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::ec2::volume', 'aws::config::configurationrecorder', 'aws::config::configrule', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::lambda::permission', 'aws::iam::role'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-SNS-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['PCI-DSS', 'GDPR'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------

