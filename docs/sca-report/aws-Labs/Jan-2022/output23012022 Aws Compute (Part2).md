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

## Aws Compute (Part2) Services

Source Repository: https://github.com/awslabs/aws-cloudformation-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac

## Compliance run Meta Data
| Title     | Description         |
|:----------|:--------------------|
| timestamp | 1642972679052       |
| snapshot  | master-snapshot_gen |
| container | scenario-aws-Labs   |
| test      | master-test.json    |

## Results

### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT58                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/redhat.template'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT59                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/suse.template'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT60                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/ubuntu.template'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT61                                                                                                             |
| structure     | filesystem                                                                                                                          |
| reference     | master                                                                                                                              |
| source        | gitConnectorAwsLabs                                                                                                                 |
| collection    | cloudformationtemplate                                                                                                              |
| type          | cloudformation                                                                                                                      |
| region        |                                                                                                                                     |
| resourceTypes | ['aws::ec2::instance']                                                                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/windows.template'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT62                                                                                                               |
| structure     | filesystem                                                                                                                            |
| reference     | master                                                                                                                                |
| source        | gitConnectorAwsLabs                                                                                                                   |
| collection    | cloudformationtemplate                                                                                                                |
| type          | cloudformation                                                                                                                        |
| region        |                                                                                                                                       |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/amazon_linux.template'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT63                                                                                                         |
| structure     | filesystem                                                                                                                      |
| reference     | master                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                             |
| collection    | cloudformationtemplate                                                                                                          |
| type          | cloudformation                                                                                                                  |
| region        |                                                                                                                                 |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/centos.template'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT64                                                                                                         |
| structure     | filesystem                                                                                                                      |
| reference     | master                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                             |
| collection    | cloudformationtemplate                                                                                                          |
| type          | cloudformation                                                                                                                  |
| region        |                                                                                                                                 |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/debian.template'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT65                                                                                                         |
| structure     | filesystem                                                                                                                      |
| reference     | master                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                             |
| collection    | cloudformationtemplate                                                                                                          |
| type          | cloudformation                                                                                                                  |
| region        |                                                                                                                                 |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/redhat.template'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT66                                                                                                       |
| structure     | filesystem                                                                                                                    |
| reference     | master                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                           |
| collection    | cloudformationtemplate                                                                                                        |
| type          | cloudformation                                                                                                                |
| region        |                                                                                                                               |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/suse.template'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT67                                                                                                         |
| structure     | filesystem                                                                                                                      |
| reference     | master                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                             |
| collection    | cloudformationtemplate                                                                                                          |
| type          | cloudformation                                                                                                                  |
| region        |                                                                                                                                 |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/ubuntu.template'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT68                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::ec2::instance']                                                                                                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/windows.template'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT70                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                       |
| reference     | master                                                                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                                                                              |
| collection    | cloudformationtemplate                                                                                                                                                           |
| type          | cloudformation                                                                                                                                                                   |
| region        |                                                                                                                                                                                  |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::vpcendpoint', 'aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnetroutetableassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

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
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::vpcendpoint', 'aws::ec2::vpc', 'aws::iam::instanceprofile', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT72                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                             |
| type          | cloudformation                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::vpcendpoint', 'aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::cloudformation::waitcondition', 'aws::ec2::subnetroutetableassociation', 'aws::cloudformation::waitconditionhandle'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

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
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::vpcendpoint', 'aws::ec2::vpc', 'aws::iam::instanceprofile', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::cloudformation::waitcondition', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

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
| resourceTypes | ['aws::ec2::instance', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::s3::bucket', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::kms::alias', 'aws::ec2::securitygroupingress', 'aws::s3::bucketpolicy', 'aws::kms::key', 'aws::elasticloadbalancingv2::loadbalancer', 'custom::lambdaversion', 'aws::ec2::securitygroupegress', 'aws::elasticloadbalancingv2::listener', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                                  |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT76                                                                                                                      |
| structure     | filesystem                                                                                                                                   |
| reference     | master                                                                                                                                       |
| source        | gitConnectorAwsLabs                                                                                                                          |
| collection    | cloudformationtemplate                                                                                                                       |
| type          | cloudformation                                                                                                                               |
| region        |                                                                                                                                              |
| resourceTypes | ['aws::ec2::instance', 'aws::ssm::association']                                                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/DirectoryADClients/templates/DIRECTORY-AD-CLIENTS.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

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
| resourceTypes | ['aws::ec2::instance', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ssm::document']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT79                                                                                                        |
| structure     | filesystem                                                                                                                     |
| reference     | master                                                                                                                         |
| source        | gitConnectorAwsLabs                                                                                                            |
| collection    | cloudformationtemplate                                                                                                         |
| type          | cloudformation                                                                                                                 |
| region        |                                                                                                                                |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/HelperNonAmaznAmi/RHEL7_cfn-hup.template'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT80                                                                                                                 |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                                     |
| collection    | cloudformationtemplate                                                                                                                  |
| type          | cloudformation                                                                                                                          |
| region        |                                                                                                                                         |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/HelperNonAmaznAmi/ubuntu16.04LTS_cfn-hup.template'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT84                                                                                                       |
| structure     | filesystem                                                                                                                    |
| reference     | master                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                           |
| collection    | cloudformationtemplate                                                                                                        |
| type          | cloudformation                                                                                                                |
| region        |                                                                                                                               |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/RHEL7_cfn-hup.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT85                                                                                                       |
| structure     | filesystem                                                                                                                    |
| reference     | master                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                           |
| collection    | cloudformationtemplate                                                                                                        |
| type          | cloudformation                                                                                                                |
| region        |                                                                                                                               |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/RHEL8_cfn-hup.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT86                                                                                                                |
| structure     | filesystem                                                                                                                             |
| reference     | master                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                 |
| type          | cloudformation                                                                                                                         |
| region        |                                                                                                                                        |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/ubuntu16.04LTS_cfn-hup.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT87                                                                                                                |
| structure     | filesystem                                                                                                                             |
| reference     | master                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                 |
| type          | cloudformation                                                                                                                         |
| region        |                                                                                                                                        |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/ubuntu18.04LTS_cfn-hup.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT88                                                                                                                |
| structure     | filesystem                                                                                                                             |
| reference     | master                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                 |
| type          | cloudformation                                                                                                                         |
| region        |                                                                                                                                        |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/ubuntu20.04LTS_cfn-hup.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

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
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::vpcendpoint', 'aws::ec2::vpc', 'aws::iam::instanceprofile', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'custom::getpl', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::cloudformation::waitcondition', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

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

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT100                                                                                                   |
| structure     | filesystem                                                                                                                 |
| reference     | master                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                        |
| collection    | cloudformationtemplate                                                                                                     |
| type          | cloudformation                                                                                                             |
| region        |                                                                                                                            |
| resourceTypes | ['aws::ec2::instance']                                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/HostnameChangeRHEL-Metadata.template'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT101                                                                                                   |
| structure     | filesystem                                                                                                                 |
| reference     | master                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                        |
| collection    | cloudformationtemplate                                                                                                     |
| type          | cloudformation                                                                                                             |
| region        |                                                                                                                            |
| resourceTypes | ['aws::ec2::instance']                                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/HostnameChangeRHEL-Userdata.template'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT102                                                                                             |
| structure     | filesystem                                                                                                           |
| reference     | master                                                                                                               |
| source        | gitConnectorAwsLabs                                                                                                  |
| collection    | cloudformationtemplate                                                                                               |
| type          | cloudformation                                                                                                       |
| region        |                                                                                                                      |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/WordPress_Single_Instance.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT103                                                                                                            |
| structure     | filesystem                                                                                                                          |
| reference     | master                                                                                                                              |
| source        | gitConnectorAwsLabs                                                                                                                 |
| collection    | cloudformationtemplate                                                                                                              |
| type          | cloudformation                                                                                                                      |
| region        |                                                                                                                                     |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::cloudformation::waitcondition', 'aws::cloudformation::waitconditionhandle'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EC2/ec2_with_waitcondition_template.json'] |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT106                                                                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                                                                                                                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | cloudformation                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::networkaclentry', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::cloudformation::waitcondition', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::networkacl', 'aws::ec2::eip'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: PR-AWS-CFR-EC2-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-ECS-001
Title: AWS ECS task definition elevated privileges enabled\
Test Result: **passed**\
Description : Ensure your ECS containers are not given elevated privileges on the host container instance. When the Privileged parameter is true, the container is given elevated privileges on the host container instance (similar to the root user). This policy checks the security configuration of your task definition and alerts if elevated privileges are enabled. Note: This parameter is not supported for Windows containers or tasks using the Fargate launch type.\

#### Test Details
- eval: data.rule.ecs_task_evelated
- id : PR-AWS-CFR-ECS-001

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
| resourceTypes | ['aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::cluster', 'aws::ecs::service', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::events::rule', 'aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-ECS-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego)
- severity: High

tags
| Title      | Description                                                        |
|:-----------|:-------------------------------------------------------------------|
| cloud      | git                                                                |
| compliance | ['HITRUST', 'GDPR', 'NIST 800', 'PCI-DSS', 'CSA-CCM', 'ISO 27001'] |
| service    | ['cloudformation']                                                 |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-ECS-002
Title: AWS ECS/Fargate task definition execution IAM Role not found\
Test Result: **failed**\
Description : The execution IAM Role is required by tasks to pull container images and publish container logs to Amazon CloudWatch on your behalf. This policy generates an alert if a task execution role is not found in your task definition.\

#### Test Details
- eval: data.rule.ecs_exec
- id : PR-AWS-CFR-ECS-002

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
| resourceTypes | ['aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::cluster', 'aws::ecs::service', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::events::rule', 'aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-ECS-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego)
- severity: Medium

tags
| Title      | Description                                                        |
|:-----------|:-------------------------------------------------------------------|
| cloud      | git                                                                |
| compliance | ['HITRUST', 'GDPR', 'NIST 800', 'PCI-DSS', 'CSA-CCM', 'ISO 27001'] |
| service    | ['cloudformation']                                                 |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-ECS-003
Title: AWS ECS/ Fargate task definition root user found\
Test Result: **passed**\
Description : The user name to use inside the container should not be root. This policy generates an alert if root user is found in your container definition. The User parameter maps to User in the Create a container section of the Docker Remote API and the --user option to docker run Note: This parameter is not supported for Windows containers.\

#### Test Details
- eval: data.rule.ecs_root_user
- id : PR-AWS-CFR-ECS-003

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
| resourceTypes | ['aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::cluster', 'aws::ecs::service', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::events::rule', 'aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-ECS-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego)
- severity: High

tags
| Title      | Description                                                        |
|:-----------|:-------------------------------------------------------------------|
| cloud      | git                                                                |
| compliance | ['HITRUST', 'GDPR', 'NIST 800', 'PCI-DSS', 'CSA-CCM', 'ISO 27001'] |
| service    | ['cloudformation']                                                 |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-ECS-004
Title: AWS ECS Task Definition readonlyRootFilesystem Not Enabled\
Test Result: **failed**\
Description : It is recommended that readonlyRootFilesystem is enabled for AWS ECS task definition. Please make sure your 'ContainerDefinitions' template has 'ReadonlyRootFilesystem' and is set to 'true'.\

#### Test Details
- eval: data.rule.ecs_root_filesystem
- id : PR-AWS-CFR-ECS-004

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
| resourceTypes | ['aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::cluster', 'aws::ecs::service', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::events::rule', 'aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-ECS-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-ECS-005
Title: AWS ECS task definition resource limits not set.\
Test Result: **failed**\
Description : It is recommended that resource limits are set for AWS ECS task definition. Please make sure attributes 'Cpu' or 'Memory' exists and its value is not set to 0 under 'TaskDefinition' or 'ContainerDefinitions'.\

#### Test Details
- eval: data.rule.ecs_resource_limit
- id : PR-AWS-CFR-ECS-005

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
| resourceTypes | ['aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::cluster', 'aws::ecs::service', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::events::rule', 'aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-ECS-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-ECS-006
Title: AWS ECS task definition logging not enabled. or only valid option for LogDriver is 'awslogs'\
Test Result: **passed**\
Description : It is recommended that logging is enabled for AWS ECS task definition. Please make sure your 'TaskDefinition' template has 'LogConfiguration' and 'LogDriver' configured.\

#### Test Details
- eval: data.rule.ecs_logging
- id : PR-AWS-CFR-ECS-006

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
| resourceTypes | ['aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::cluster', 'aws::ecs::service', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::events::rule', 'aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-ECS-006
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['NIST 800']       |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-ECS-007
Title: Ensure EFS volumes in ECS task definitions have encryption in transit enabled\
Test Result: **failed**\
Description : ECS task definitions that have volumes using EFS configuration should explicitly enable in transit encryption to prevent the risk of data loss due to interception.\

#### Test Details
- eval: data.rule.ecs_transit_enabled
- id : PR-AWS-CFR-ECS-007

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
| resourceTypes | ['aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::cluster', 'aws::ecs::service', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::events::rule', 'aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-ECS-007
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-ECS-008
Title: Ensure container insights are enabled on ECS cluster\
Test Result: **failed**\
Description : Container Insights can be used to collect, aggregate, and summarize metrics and logs from containerized applications and microservices. They can also be extended to collect metrics at the cluster, task, and service levels. Using Container Insights allows you to monitor, troubleshoot, and set alarms for all your Amazon ECS resources. It provides a simple to use native and fully managed service for managing ECS issues.\

#### Test Details
- eval: data.rule.ecs_container_insight_enable
- id : PR-AWS-CFR-ECS-008

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
| resourceTypes | ['aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::cluster', 'aws::ecs::service', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::events::rule', 'aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-ECS-008
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-ECS-009
Title: Ensure ECS Services and Task Set EnableExecuteCommand property set to False\
Test Result: **passed**\
Description : If the EnableExecuteCommand property is set to True on an ECS Service then any third person can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations.\

#### Test Details
- eval: data.rule.ecs_enable_execute_command
- id : PR-AWS-CFR-ECS-009

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
| resourceTypes | ['aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::cluster', 'aws::ecs::service', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::events::rule', 'aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-ECS-009
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-ECS-010
Title: Ensure that ECS Service and Task Set network configuration disallows the assignment of public IPs\
Test Result: **passed**\
Description : Ensure that the ecs service and Task Set Network has set [AssignPublicIp/assign_public_ip] property is set to DISABLED else an Actor can exfiltrate data by associating ECS resources with non-ADATUM resources\

#### Test Details
- eval: data.rule.ecs_assign_public_ip
- id : PR-AWS-CFR-ECS-010

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
| resourceTypes | ['aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::cluster', 'aws::ecs::service', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::events::rule', 'aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-ECS-010
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-ECS-011
Title: Ensure that ECS services and Task Sets are launched as Fargate type\
Test Result: **failed**\
Description : Ensure that ECS services and Task Sets are launched as Fargate type else Actor can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations\

#### Test Details
- eval: data.rule.ecs_launch_type
- id : PR-AWS-CFR-ECS-011

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
| resourceTypes | ['aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::cluster', 'aws::ecs::service', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::events::rule', 'aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-ECS-011
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-ECS-012
Title: Value(s) of subnets attached to aws ecs service or taskset AwsVpcConfiguration resources are vended\
Test Result: **failed**\
Description : Value(s) of subnets attached to aws ecs service or taskset AwsVpcConfiguration resources are vended else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.\

#### Test Details
- eval: data.rule.ecs_subnet
- id : PR-AWS-CFR-ECS-012

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
| resourceTypes | ['aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::cluster', 'aws::ecs::service', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::events::rule', 'aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-ECS-012
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-ECS-013
Title: VPC configurations on ECS Services and TaskSets must use either vended security groups\
Test Result: **failed**\
Description : ECS Service and ECS TaskSet resources set a SecurityGroup in the AwsvpcConfiguration. else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.\

#### Test Details
- eval: data.rule.ecs_security_group
- id : PR-AWS-CFR-ECS-013

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
| resourceTypes | ['aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::cluster', 'aws::ecs::service', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::events::rule', 'aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-ECS-013
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-ECS-014
Title: Ensure that ECS Task Definition have their network mode property set to awsvpc\
Test Result: **failed**\
Description : Ensure that ECS Task Definition have their network mode property set to awsvpc. else an Actor can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations\

#### Test Details
- eval: data.rule.ecs_network_mode
- id : PR-AWS-CFR-ECS-014

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
| resourceTypes | ['aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::cluster', 'aws::ecs::service', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::events::rule', 'aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-ECS-014
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ecs.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::permission', 'aws::cloudformation::macro', 'aws::lambda::function']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Macro.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::permission', 'aws::cloudformation::macro', 'aws::lambda::function']                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::permission', 'aws::cloudformation::macro', 'aws::lambda::function']                                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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
| resourceTypes | ['aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::elasticache::replicationgroup', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::parametergroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::elasticache::subnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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
| resourceTypes | ['aws::config::configurationrecorder', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::iam::role', 'aws::ec2::volume', 'aws::config::configrule', 'aws::lambda::permission', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::sns::topic'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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
| resourceTypes | ['aws::ec2::vpcdhcpoptionsassociation', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::logs::loggroup', 'aws::iam::role', 'aws::secretsmanager::secret', 'aws::lambda::function', 'custom::adconnectorresource', 'aws::ec2::dhcpoptions'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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
| resourceTypes | ['aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::iam::role', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::kms::key', 'custom::lambdatrig', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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
| resourceTypes | ['aws::ec2::instance', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::s3::bucket', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::kms::alias', 'aws::ec2::securitygroupingress', 'aws::s3::bucketpolicy', 'aws::kms::key', 'aws::elasticloadbalancingv2::loadbalancer', 'custom::lambdaversion', 'aws::ec2::securitygroupegress', 'aws::elasticloadbalancingv2::listener', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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
| resourceTypes | ['aws::iam::role', 'custom::vpceinterface', 'aws::lambda::function']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/createVPCInterfaceEndpoint/lambda_vpce_interface.json'] |

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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
| resourceTypes | ['custom::directorysettingsresource', 'aws::logs::loggroup', 'aws::iam::role', 'aws::lambda::function', 'aws::sns::topic']                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/DirectoryServiceSettings/templates/DIRECTORY_SETTINGS.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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
| resourceTypes | ['aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::internetgateway', 'aws::lambda::function', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::natgateway', 'aws::ec2::eip'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/LambaStaticIP/lambda-static.cfn.yaml']                                                                                                                                                   |

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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
| resourceTypes | ['custom::routetablelambda', 'aws::ec2::vpc', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::lambda::function', 'aws::ec2::vpcgatewayattachment']          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/lambda-backed-cloudformation-custom-resources/get_vpc_main_route_table_id/RouteTable.template'] |

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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
| resourceTypes | ['aws::iam::role', 'aws::logs::loggroup', 'aws::lambda::function']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/function-template.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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
| resourceTypes | ['aws::iam::role', 'aws::logs::loggroup', 'aws::lambda::function']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/Templates/stackset-function-template.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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
| resourceTypes | ['aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::elasticache::replicationgroup', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::parametergroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::elasticache::subnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-CFR-LMD-001

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

- masterTestId: PR-AWS-CFR-LMD-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                         |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::permission', 'aws::cloudformation::macro', 'aws::lambda::function']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Macro.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::permission', 'aws::cloudformation::macro', 'aws::lambda::function']                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::permission', 'aws::cloudformation::macro', 'aws::lambda::function']                                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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
| resourceTypes | ['aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::elasticache::replicationgroup', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::parametergroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::elasticache::subnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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
| resourceTypes | ['aws::config::configurationrecorder', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::iam::role', 'aws::ec2::volume', 'aws::config::configrule', 'aws::lambda::permission', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::sns::topic'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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
| resourceTypes | ['aws::ec2::vpcdhcpoptionsassociation', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::logs::loggroup', 'aws::iam::role', 'aws::secretsmanager::secret', 'aws::lambda::function', 'custom::adconnectorresource', 'aws::ec2::dhcpoptions'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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
| resourceTypes | ['aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::iam::role', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::kms::key', 'custom::lambdatrig', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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
| resourceTypes | ['aws::ec2::instance', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::s3::bucket', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::kms::alias', 'aws::ec2::securitygroupingress', 'aws::s3::bucketpolicy', 'aws::kms::key', 'aws::elasticloadbalancingv2::loadbalancer', 'custom::lambdaversion', 'aws::ec2::securitygroupegress', 'aws::elasticloadbalancingv2::listener', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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
| resourceTypes | ['aws::iam::role', 'custom::vpceinterface', 'aws::lambda::function']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/createVPCInterfaceEndpoint/lambda_vpce_interface.json'] |

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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
| resourceTypes | ['custom::directorysettingsresource', 'aws::logs::loggroup', 'aws::iam::role', 'aws::lambda::function', 'aws::sns::topic']                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/DirectoryServiceSettings/templates/DIRECTORY_SETTINGS.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **passed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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
| resourceTypes | ['aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::internetgateway', 'aws::lambda::function', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::natgateway', 'aws::ec2::eip'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/LambaStaticIP/lambda-static.cfn.yaml']                                                                                                                                                   |

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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
| resourceTypes | ['custom::routetablelambda', 'aws::ec2::vpc', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::lambda::function', 'aws::ec2::vpcgatewayattachment']          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/lambda-backed-cloudformation-custom-resources/get_vpc_main_route_table_id/RouteTable.template'] |

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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
| resourceTypes | ['aws::iam::role', 'aws::logs::loggroup', 'aws::lambda::function']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/function-template.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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
| resourceTypes | ['aws::iam::role', 'aws::logs::loggroup', 'aws::lambda::function']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/Templates/stackset-function-template.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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
| resourceTypes | ['aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::elasticache::replicationgroup', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::parametergroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::elasticache::subnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-CFR-LMD-002

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

- masterTestId: PR-AWS-CFR-LMD-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['PCI-DSS']        |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::permission', 'aws::cloudformation::macro', 'aws::lambda::function']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Macro.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::permission', 'aws::cloudformation::macro', 'aws::lambda::function']                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::permission', 'aws::cloudformation::macro', 'aws::lambda::function']                                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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
| resourceTypes | ['aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::elasticache::replicationgroup', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::parametergroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::elasticache::subnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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
| resourceTypes | ['aws::config::configurationrecorder', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::iam::role', 'aws::ec2::volume', 'aws::config::configrule', 'aws::lambda::permission', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::sns::topic'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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
| resourceTypes | ['aws::ec2::vpcdhcpoptionsassociation', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::logs::loggroup', 'aws::iam::role', 'aws::secretsmanager::secret', 'aws::lambda::function', 'custom::adconnectorresource', 'aws::ec2::dhcpoptions'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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
| resourceTypes | ['aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::iam::role', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::kms::key', 'custom::lambdatrig', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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
| resourceTypes | ['aws::ec2::instance', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::s3::bucket', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::kms::alias', 'aws::ec2::securitygroupingress', 'aws::s3::bucketpolicy', 'aws::kms::key', 'aws::elasticloadbalancingv2::loadbalancer', 'custom::lambdaversion', 'aws::ec2::securitygroupegress', 'aws::elasticloadbalancingv2::listener', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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
| resourceTypes | ['aws::iam::role', 'custom::vpceinterface', 'aws::lambda::function']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/createVPCInterfaceEndpoint/lambda_vpce_interface.json'] |

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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
| resourceTypes | ['custom::directorysettingsresource', 'aws::logs::loggroup', 'aws::iam::role', 'aws::lambda::function', 'aws::sns::topic']                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/DirectoryServiceSettings/templates/DIRECTORY_SETTINGS.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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
| resourceTypes | ['aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::internetgateway', 'aws::lambda::function', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::natgateway', 'aws::ec2::eip'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/LambaStaticIP/lambda-static.cfn.yaml']                                                                                                                                                   |

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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
| resourceTypes | ['custom::routetablelambda', 'aws::ec2::vpc', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::lambda::function', 'aws::ec2::vpcgatewayattachment']          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/lambda-backed-cloudformation-custom-resources/get_vpc_main_route_table_id/RouteTable.template'] |

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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
| resourceTypes | ['aws::iam::role', 'aws::logs::loggroup', 'aws::lambda::function']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/function-template.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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
| resourceTypes | ['aws::iam::role', 'aws::logs::loggroup', 'aws::lambda::function']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/Templates/stackset-function-template.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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
| resourceTypes | ['aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::elasticache::replicationgroup', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::parametergroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::elasticache::subnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-CFR-LMD-003

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

- masterTestId: PR-AWS-CFR-LMD-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::permission', 'aws::cloudformation::macro', 'aws::lambda::function']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Macro.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::permission', 'aws::cloudformation::macro', 'aws::lambda::function']                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::permission', 'aws::cloudformation::macro', 'aws::lambda::function']                                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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
| resourceTypes | ['aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::elasticache::replicationgroup', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::parametergroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::elasticache::subnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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
| resourceTypes | ['aws::config::configurationrecorder', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::iam::role', 'aws::ec2::volume', 'aws::config::configrule', 'aws::lambda::permission', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::sns::topic'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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
| resourceTypes | ['aws::ec2::vpcdhcpoptionsassociation', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::logs::loggroup', 'aws::iam::role', 'aws::secretsmanager::secret', 'aws::lambda::function', 'custom::adconnectorresource', 'aws::ec2::dhcpoptions'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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
| resourceTypes | ['aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::iam::role', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::kms::key', 'custom::lambdatrig', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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
| resourceTypes | ['aws::ec2::instance', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::s3::bucket', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::kms::alias', 'aws::ec2::securitygroupingress', 'aws::s3::bucketpolicy', 'aws::kms::key', 'aws::elasticloadbalancingv2::loadbalancer', 'custom::lambdaversion', 'aws::ec2::securitygroupegress', 'aws::elasticloadbalancingv2::listener', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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
| resourceTypes | ['aws::iam::role', 'custom::vpceinterface', 'aws::lambda::function']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/createVPCInterfaceEndpoint/lambda_vpce_interface.json'] |

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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
| resourceTypes | ['custom::directorysettingsresource', 'aws::logs::loggroup', 'aws::iam::role', 'aws::lambda::function', 'aws::sns::topic']                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/DirectoryServiceSettings/templates/DIRECTORY_SETTINGS.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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
| resourceTypes | ['aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::internetgateway', 'aws::lambda::function', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::natgateway', 'aws::ec2::eip'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/LambaStaticIP/lambda-static.cfn.yaml']                                                                                                                                                   |

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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
| resourceTypes | ['custom::routetablelambda', 'aws::ec2::vpc', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::lambda::function', 'aws::ec2::vpcgatewayattachment']          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/lambda-backed-cloudformation-custom-resources/get_vpc_main_route_table_id/RouteTable.template'] |

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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
| resourceTypes | ['aws::iam::role', 'aws::logs::loggroup', 'aws::lambda::function']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/function-template.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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
| resourceTypes | ['aws::iam::role', 'aws::logs::loggroup', 'aws::lambda::function']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/Templates/stackset-function-template.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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
| resourceTypes | ['aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::elasticache::replicationgroup', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::parametergroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::elasticache::subnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-CFR-LMD-004

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

- masterTestId: PR-AWS-CFR-LMD-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::permission', 'aws::cloudformation::macro', 'aws::lambda::function']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Macro.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::permission', 'aws::cloudformation::macro', 'aws::lambda::function']                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::permission', 'aws::cloudformation::macro', 'aws::lambda::function']                                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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
| resourceTypes | ['aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::elasticache::replicationgroup', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::parametergroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::elasticache::subnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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
| resourceTypes | ['aws::config::configurationrecorder', 'aws::s3::bucket', 'aws::config::deliverychannel', 'aws::iam::role', 'aws::ec2::volume', 'aws::config::configrule', 'aws::lambda::permission', 'aws::lambda::function', 'aws::sns::topicpolicy', 'aws::sns::topic'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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
| resourceTypes | ['aws::ec2::vpcdhcpoptionsassociation', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::logs::loggroup', 'aws::iam::role', 'aws::secretsmanager::secret', 'aws::lambda::function', 'custom::adconnectorresource', 'aws::ec2::dhcpoptions'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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
| resourceTypes | ['aws::s3::bucket', 'aws::iam::managedpolicy', 'aws::iam::role', 'aws::kms::alias', 'aws::s3::bucketpolicy', 'aws::kms::key', 'custom::lambdatrig', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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
| resourceTypes | ['aws::ec2::instance', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::s3::bucket', 'aws::ec2::securitygroup', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::kms::alias', 'aws::ec2::securitygroupingress', 'aws::s3::bucketpolicy', 'aws::kms::key', 'aws::elasticloadbalancingv2::loadbalancer', 'custom::lambdaversion', 'aws::ec2::securitygroupegress', 'aws::elasticloadbalancingv2::listener', 'aws::lambda::function'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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
| resourceTypes | ['aws::iam::role', 'custom::vpceinterface', 'aws::lambda::function']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/createVPCInterfaceEndpoint/lambda_vpce_interface.json'] |

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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
| resourceTypes | ['custom::directorysettingsresource', 'aws::logs::loggroup', 'aws::iam::role', 'aws::lambda::function', 'aws::sns::topic']                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/DirectoryServiceSettings/templates/DIRECTORY_SETTINGS.cfn.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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
| resourceTypes | ['aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::internetgateway', 'aws::lambda::function', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::natgateway', 'aws::ec2::eip'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/LambaStaticIP/lambda-static.cfn.yaml']                                                                                                                                                   |

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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
| resourceTypes | ['custom::routetablelambda', 'aws::ec2::vpc', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::lambda::function', 'aws::ec2::vpcgatewayattachment']          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/lambda-backed-cloudformation-custom-resources/get_vpc_main_route_table_id/RouteTable.template'] |

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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
| resourceTypes | ['aws::iam::role', 'aws::logs::loggroup', 'aws::lambda::function']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/function-template.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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
| resourceTypes | ['aws::iam::role', 'aws::logs::loggroup', 'aws::lambda::function']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/Templates/stackset-function-template.yaml'] |

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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
| resourceTypes | ['aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::iam::role', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::elasticache::replicationgroup', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::parametergroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::elasticache::subnetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **failed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-CFR-LMD-005

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

- masterTestId: PR-AWS-CFR-LMD-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/lambda.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------

