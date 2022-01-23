# Automated Vulnerability Scan result and Static Code Analysis for Amazon Web Services Labs (Jan 2022)

## All Services

#### Compute (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Jan-2022/output23012022%20Aws%20Compute%20(Part1).md
#### Compute (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Jan-2022/output23012022%20Aws%20Compute%20(Part2).md
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

## Aws Compute (Part1) Services

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

### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT9                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                                                                                                                    |
| type          | cloudformation                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                           |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

#### Snapshots
| Title         | Description                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT15                                                                                                       |
| structure     | filesystem                                                                                                                    |
| reference     | master                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                           |
| collection    | cloudformationtemplate                                                                                                        |
| type          | cloudformation                                                                                                                |
| region        |                                                                                                                               |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/FindInMap_Inside_Sub.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT16                                                                                                                  |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                   |
| type          | cloudformation                                                                                                                           |
| region        |                                                                                                                                          |
| resourceTypes | ['aws::ec2::instance']                                                                                                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/HostnameChangeRHEL-Metadata.template'] |

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT17                                                                                                                  |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                   |
| type          | cloudformation                                                                                                                           |
| region        |                                                                                                                                          |
| resourceTypes | ['aws::ec2::instance']                                                                                                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/HostnameChangeRHEL-Userdata.template'] |

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT22                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2InstanceWithSecurityGroupSample.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT23                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2_Instance_With_Ephemeral_Drives.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

#### Snapshots
| Title         | Description                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT24                                                                                            |
| structure     | filesystem                                                                                                         |
| reference     | master                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                |
| collection    | cloudformationtemplate                                                                                             |
| type          | cloudformation                                                                                                     |
| region        |                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::ec2::eipassociation', 'aws::ec2::eip']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT28                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT55                                                                                                                  |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                   |
| type          | cloudformation                                                                                                                           |
| region        |                                                                                                                                          |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/amazon_linux.template'] |

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT56                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/centos.template'] |

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT57                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/debian.template'] |

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **passed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **passed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **passed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **passed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **passed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **passed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-CFR-EC2-001

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

- masterTestId: PR-AWS-CFR-EC2-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['cloudformation']  |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT9                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                                                                                                                    |
| type          | cloudformation                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                           |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

#### Snapshots
| Title         | Description                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT15                                                                                                       |
| structure     | filesystem                                                                                                                    |
| reference     | master                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                           |
| collection    | cloudformationtemplate                                                                                                        |
| type          | cloudformation                                                                                                                |
| region        |                                                                                                                               |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/FindInMap_Inside_Sub.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT16                                                                                                                  |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                   |
| type          | cloudformation                                                                                                                           |
| region        |                                                                                                                                          |
| resourceTypes | ['aws::ec2::instance']                                                                                                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/HostnameChangeRHEL-Metadata.template'] |

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT17                                                                                                                  |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                   |
| type          | cloudformation                                                                                                                           |
| region        |                                                                                                                                          |
| resourceTypes | ['aws::ec2::instance']                                                                                                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/HostnameChangeRHEL-Userdata.template'] |

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT22                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2InstanceWithSecurityGroupSample.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT23                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2_Instance_With_Ephemeral_Drives.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

#### Snapshots
| Title         | Description                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT24                                                                                            |
| structure     | filesystem                                                                                                         |
| reference     | master                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                |
| collection    | cloudformationtemplate                                                                                             |
| type          | cloudformation                                                                                                     |
| region        |                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::ec2::eipassociation', 'aws::ec2::eip']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT28                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT55                                                                                                                  |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                   |
| type          | cloudformation                                                                                                                           |
| region        |                                                                                                                                          |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/amazon_linux.template'] |

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT56                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/centos.template'] |

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT57                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/debian.template'] |

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-CFR-EC2-002

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

- masterTestId: PR-AWS-CFR-EC2-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT9                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                                                                                                                    |
| type          | cloudformation                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                           |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

#### Snapshots
| Title         | Description                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT15                                                                                                       |
| structure     | filesystem                                                                                                                    |
| reference     | master                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                           |
| collection    | cloudformationtemplate                                                                                                        |
| type          | cloudformation                                                                                                                |
| region        |                                                                                                                               |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/FindInMap_Inside_Sub.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT16                                                                                                                  |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                   |
| type          | cloudformation                                                                                                                           |
| region        |                                                                                                                                          |
| resourceTypes | ['aws::ec2::instance']                                                                                                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/HostnameChangeRHEL-Metadata.template'] |

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT17                                                                                                                  |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                   |
| type          | cloudformation                                                                                                                           |
| region        |                                                                                                                                          |
| resourceTypes | ['aws::ec2::instance']                                                                                                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/HostnameChangeRHEL-Userdata.template'] |

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT22                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2InstanceWithSecurityGroupSample.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT23                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2_Instance_With_Ephemeral_Drives.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

#### Snapshots
| Title         | Description                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT24                                                                                            |
| structure     | filesystem                                                                                                         |
| reference     | master                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                |
| collection    | cloudformationtemplate                                                                                             |
| type          | cloudformation                                                                                                     |
| region        |                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::ec2::eipassociation', 'aws::ec2::eip']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT28                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT55                                                                                                                  |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                   |
| type          | cloudformation                                                                                                                           |
| region        |                                                                                                                                          |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/amazon_linux.template'] |

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT56                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/centos.template'] |

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT57                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/debian.template'] |

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-CFR-EC2-003

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

- masterTestId: PR-AWS-CFR-EC2-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']             |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT9                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                                                                                                                    |
| type          | cloudformation                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                           |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

#### Snapshots
| Title         | Description                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT15                                                                                                       |
| structure     | filesystem                                                                                                                    |
| reference     | master                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                           |
| collection    | cloudformationtemplate                                                                                                        |
| type          | cloudformation                                                                                                                |
| region        |                                                                                                                               |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/FindInMap_Inside_Sub.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT16                                                                                                                  |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                   |
| type          | cloudformation                                                                                                                           |
| region        |                                                                                                                                          |
| resourceTypes | ['aws::ec2::instance']                                                                                                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/HostnameChangeRHEL-Metadata.template'] |

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT17                                                                                                                  |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                   |
| type          | cloudformation                                                                                                                           |
| region        |                                                                                                                                          |
| resourceTypes | ['aws::ec2::instance']                                                                                                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/HostnameChangeRHEL-Userdata.template'] |

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT22                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2InstanceWithSecurityGroupSample.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT23                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2_Instance_With_Ephemeral_Drives.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

#### Snapshots
| Title         | Description                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT24                                                                                            |
| structure     | filesystem                                                                                                         |
| reference     | master                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                |
| collection    | cloudformationtemplate                                                                                             |
| type          | cloudformation                                                                                                     |
| region        |                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::ec2::eipassociation', 'aws::ec2::eip']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT28                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT55                                                                                                                  |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                   |
| type          | cloudformation                                                                                                                           |
| region        |                                                                                                                                          |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/amazon_linux.template'] |

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT56                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/centos.template'] |

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT57                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/debian.template'] |

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-CFR-EC2-004

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

- masterTestId: PR-AWS-CFR-EC2-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better Janisio2s on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT9                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                                                                                                                    |
| type          | cloudformation                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                           |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::subnet', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::internetgateway', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

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
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better Janisio2s on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT15                                                                                                       |
| structure     | filesystem                                                                                                                    |
| reference     | master                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                           |
| collection    | cloudformationtemplate                                                                                                        |
| type          | cloudformation                                                                                                                |
| region        |                                                                                                                               |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/FindInMap_Inside_Sub.yaml'] |

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
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better Janisio2s on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT16                                                                                                                  |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                   |
| type          | cloudformation                                                                                                                           |
| region        |                                                                                                                                          |
| resourceTypes | ['aws::ec2::instance']                                                                                                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/HostnameChangeRHEL-Metadata.template'] |

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
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better Janisio2s on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT17                                                                                                                  |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                   |
| type          | cloudformation                                                                                                                           |
| region        |                                                                                                                                          |
| resourceTypes | ['aws::ec2::instance']                                                                                                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/HostnameChangeRHEL-Userdata.template'] |

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
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better Janisio2s on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT22                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2InstanceWithSecurityGroupSample.yaml'] |

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
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better Janisio2s on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT23                                                                                                          |
| structure     | filesystem                                                                                                                       |
| reference     | master                                                                                                                           |
| source        | gitConnectorAwsLabs                                                                                                              |
| collection    | cloudformationtemplate                                                                                                           |
| type          | cloudformation                                                                                                                   |
| region        |                                                                                                                                  |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2_Instance_With_Ephemeral_Drives.yaml'] |

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
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better Janisio2s on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT24                                                                                            |
| structure     | filesystem                                                                                                         |
| reference     | master                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                |
| collection    | cloudformationtemplate                                                                                             |
| type          | cloudformation                                                                                                     |
| region        |                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::ec2::eipassociation', 'aws::ec2::eip']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

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
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better Janisio2s on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT28                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

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
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better Janisio2s on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT55                                                                                                                  |
| structure     | filesystem                                                                                                                               |
| reference     | master                                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                                      |
| collection    | cloudformationtemplate                                                                                                                   |
| type          | cloudformation                                                                                                                           |
| region        |                                                                                                                                          |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/amazon_linux.template'] |

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
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better Janisio2s on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT56                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/centos.template'] |

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
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better Janisio2s on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-CFR-EC2-005

#### Snapshots
| Title         | Description                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT57                                                                                                            |
| structure     | filesystem                                                                                                                         |
| reference     | master                                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                                |
| collection    | cloudformationtemplate                                                                                                             |
| type          | cloudformation                                                                                                                     |
| region        |                                                                                                                                    |
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/debian.template'] |

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

