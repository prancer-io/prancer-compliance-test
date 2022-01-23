# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AWS (Jan 2022)

## All Services

#### Compute: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Compute.md
#### Data Store: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20DataStore.md
#### Management: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Management.md
#### Networking (Part1): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Networking%20(Part1).md
#### Networking (Part2): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Networking%20(Part2).md
#### Networking (Part3): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Networking%20(Part3).md
#### Security: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Security.md

## Terraform Aws Management Services

Source Repository: https://github.com/hashicorp/terraform-provider-aws

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform

## Compliance run Meta Data
| Title     | Description                      |
|:----------|:---------------------------------|
| timestamp | 1642966337770                    |
| snapshot  | master-snapshot_gen              |
| container | scenario-aws-terraform-hashicorp |
| test      | master-test.json                 |

## Results

### Test ID - PR-AWS-TRF-SNS-002
Title: AWS SNS topic encrypted using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.\

#### Test Details
- eval: data.rule.sns_encrypt_key
- id : PR-AWS-TRF-SNS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT20                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['aws_cloudwatch_event_target', 'aws_sns_topic', 'aws_cloudwatch_event_rule']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/events/sns/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/events/sns/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/events/sns/main.tf'] |

- masterTestId: PR-AWS-TRF-SNS-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/sns.rego)
- severity: High

tags
| Title      | Description          |
|:-----------|:---------------------|
| cloud      | git                  |
| compliance | ['GDPR', 'NIST 800'] |
| service    | ['terraform']        |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SNS-003
Title: AWS SNS topic with server-side encryption disabled\
Test Result: **failed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.\

#### Test Details
- eval: data.rule.sns_encrypt
- id : PR-AWS-TRF-SNS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT20                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['aws_cloudwatch_event_target', 'aws_sns_topic', 'aws_cloudwatch_event_rule']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/events/sns/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/events/sns/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/events/sns/main.tf'] |

- masterTestId: PR-AWS-TRF-SNS-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/sns.rego)
- severity: High

tags
| Title      | Description                              |
|:-----------|:-----------------------------------------|
| cloud      | git                                      |
| compliance | ['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800'] |
| service    | ['terraform']                            |
----------------------------------------------------------------

