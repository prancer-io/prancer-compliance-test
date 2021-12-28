# Automated Vulnerability Scan result and Static Code Analysis for Amazon Web Services Labs (Dec 2021)

## All Services

#### Compute: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Compute.md
#### DataStore (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20DataStore%20(Part1).md
#### DataStore (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20DataStore%20(Part2).md
#### Management: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Management.md
#### Networking (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Networking%20(Part1).md
#### Networking (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Networking%20(Part2).md
#### Networking (Part3): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Networking%20(Part3).md
#### Networking (Part4): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Networking%20(Part4).md
#### Networking (Part5): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Networking%20(Part5).md
#### Networking (Part6): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Networking%20(Part6).md
#### Networking (Part7): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Networking%20(Part7).md
#### Security: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/Dec-2021/output12232021%20Aws%20Security.md

## AWS Networking (Part5) Services

Source Repository: https://github.com/awslabs/aws-cloudformation-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac

## Compliance run Meta Data
| Title     | Description         |
|:----------|:--------------------|
| timestamp | 1640412719605       |
| snapshot  | master-snapshot_gen |
| container | scenario-aws-Labs   |
| test      | master-test.json    |

## Results

### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ssm::document', 'aws::ec2::instance']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::dhcpoptions', 'aws::secretsmanager::secret', 'aws::iam::instanceprofile', 'aws::directoryservice::microsoftad', 'aws::ec2::securitygroup', 'aws::ec2::vpcdhcpoptionsassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ManagedAD/templates/MANAGEDAD.cfn.yaml']                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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
| resourceTypes | ['aws::iam::role', 'custom::getpl', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::subnetgroup', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::elasticache::replicationgroup', 'aws::ec2::vpc', 'custom::region', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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
| resourceTypes | ['aws::cloudformation::waitcondition', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::instance', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EC2/ec2_with_waitcondition_template.json'] |

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::efs::mounttarget', 'aws::ec2::securitygroup', 'aws::efs::filesystem', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EFS/efs_with_automount_to_ec2.json']                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-CFR-SG-020

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
| resourceTypes | ['aws::ec2::networkaclentry', 'aws::ec2::internetgateway', 'aws::ec2::eip', 'aws::ec2::routetable', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::securitygroup', 'aws::ec2::networkacl', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: TEST_SECURITY_GROUP_20
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::sns::topic', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml']                                                                      |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

#### Snapshots
| Title         | Description                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT3                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                                                                     |
| type          | cloudformation                                                                                                                                                                             |
| region        |                                                                                                                                                                                            |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::scheduledaction', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingScheduledAction.yaml']                                                           |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::subnetgroup', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::elasticache::replicationgroup', 'aws::ec2::vpc', 'custom::region', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::iam::role', 'aws::dms::replicationtask', 'aws::ec2::internetgateway', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationsubnetgroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::dms::endpoint', 'aws::rds::dbcluster', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::rds::dbinstance', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::ec2::eipassociation', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::ec2::eip']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::ecs::service', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::ecs::taskdefinition', 'aws::autoscaling::launchconfiguration', 'aws::logs::loggroup', 'aws::autoscaling::autoscalinggroup', 'aws::events::rule', 'aws::applicationautoscaling::scalabletarget', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalingpolicy', 'aws::cloudwatch::alarm', 'aws::ecs::cluster', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBGuidedAutoScalingRollingUpgrade.yaml']                                                    |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::elasticloadbalancing::loadbalancer']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

#### Snapshots
| Title         | Description                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT29                                                                                                                               |
| structure     | filesystem                                                                                                                                            |
| reference     | master                                                                                                                                                |
| source        | gitConnectorAwsLabs                                                                                                                                   |
| collection    | cloudformationtemplate                                                                                                                                |
| type          | cloudformation                                                                                                                                        |
| region        |                                                                                                                                                       |
| resourceTypes | ['aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBWithLockedDownAutoScaledInstances.yaml']   |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::neptune::dbparametergroup', 'aws::neptune::dbinstance', 'aws::iam::role', 'aws::sns::subscription', 'aws::sns::topic', 'aws::ec2::securitygroup', 'aws::neptune::dbclusterparametergroup', 'aws::neptune::dbcluster', 'aws::iam::managedpolicy', 'aws::neptune::dbsubnetgroup', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbsecuritygroup', 'aws::ec2::securitygroup']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::dhcpoptions', 'aws::secretsmanager::secret', 'aws::iam::instanceprofile', 'aws::lambda::function', 'aws::ec2::securitygroup', 'aws::logs::loggroup', 'aws::ec2::vpcdhcpoptionsassociation', 'custom::adconnectorresource'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ssm::document', 'aws::ec2::instance']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::dhcpoptions', 'aws::secretsmanager::secret', 'aws::iam::instanceprofile', 'aws::directoryservice::microsoftad', 'aws::ec2::securitygroup', 'aws::ec2::vpcdhcpoptionsassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ManagedAD/templates/MANAGEDAD.cfn.yaml']                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::iam::role', 'custom::getpl', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::subnetgroup', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::elasticache::replicationgroup', 'aws::ec2::vpc', 'custom::region', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::cloudformation::waitcondition', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::instance', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EC2/ec2_with_waitcondition_template.json'] |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::efs::mounttarget', 'aws::ec2::securitygroup', 'aws::efs::filesystem', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EFS/efs_with_automount_to_ec2.json']                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-CFR-SG-021

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
| resourceTypes | ['aws::ec2::networkaclentry', 'aws::ec2::internetgateway', 'aws::ec2::eip', 'aws::ec2::routetable', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::securitygroup', 'aws::ec2::networkacl', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: TEST_SECURITY_GROUP_21
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::sns::topic', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml']                                                                      |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

#### Snapshots
| Title         | Description                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT3                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                                                                     |
| type          | cloudformation                                                                                                                                                                             |
| region        |                                                                                                                                                                                            |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::scheduledaction', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingScheduledAction.yaml']                                                           |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::subnetgroup', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::elasticache::replicationgroup', 'aws::ec2::vpc', 'custom::region', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::iam::role', 'aws::dms::replicationtask', 'aws::ec2::internetgateway', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationsubnetgroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::dms::endpoint', 'aws::rds::dbcluster', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::rds::dbinstance', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::ec2::eipassociation', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::ec2::eip']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::ecs::service', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::ecs::taskdefinition', 'aws::autoscaling::launchconfiguration', 'aws::logs::loggroup', 'aws::autoscaling::autoscalinggroup', 'aws::events::rule', 'aws::applicationautoscaling::scalabletarget', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalingpolicy', 'aws::cloudwatch::alarm', 'aws::ecs::cluster', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBGuidedAutoScalingRollingUpgrade.yaml']                                                    |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::elasticloadbalancing::loadbalancer']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

#### Snapshots
| Title         | Description                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT29                                                                                                                               |
| structure     | filesystem                                                                                                                                            |
| reference     | master                                                                                                                                                |
| source        | gitConnectorAwsLabs                                                                                                                                   |
| collection    | cloudformationtemplate                                                                                                                                |
| type          | cloudformation                                                                                                                                        |
| region        |                                                                                                                                                       |
| resourceTypes | ['aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBWithLockedDownAutoScaledInstances.yaml']   |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **passed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::neptune::dbparametergroup', 'aws::neptune::dbinstance', 'aws::iam::role', 'aws::sns::subscription', 'aws::sns::topic', 'aws::ec2::securitygroup', 'aws::neptune::dbclusterparametergroup', 'aws::neptune::dbcluster', 'aws::iam::managedpolicy', 'aws::neptune::dbsubnetgroup', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbsecuritygroup', 'aws::ec2::securitygroup']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **passed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::dhcpoptions', 'aws::secretsmanager::secret', 'aws::iam::instanceprofile', 'aws::lambda::function', 'aws::ec2::securitygroup', 'aws::logs::loggroup', 'aws::ec2::vpcdhcpoptionsassociation', 'custom::adconnectorresource'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **passed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **passed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **passed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **passed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **passed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ssm::document', 'aws::ec2::instance']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **passed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::dhcpoptions', 'aws::secretsmanager::secret', 'aws::iam::instanceprofile', 'aws::directoryservice::microsoftad', 'aws::ec2::securitygroup', 'aws::ec2::vpcdhcpoptionsassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ManagedAD/templates/MANAGEDAD.cfn.yaml']                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **passed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::iam::role', 'custom::getpl', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::subnetgroup', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::elasticache::replicationgroup', 'aws::ec2::vpc', 'custom::region', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::cloudformation::waitcondition', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::instance', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EC2/ec2_with_waitcondition_template.json'] |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::efs::mounttarget', 'aws::ec2::securitygroup', 'aws::efs::filesystem', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EFS/efs_with_automount_to_ec2.json']                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-CFR-SG-022

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
| resourceTypes | ['aws::ec2::networkaclentry', 'aws::ec2::internetgateway', 'aws::ec2::eip', 'aws::ec2::routetable', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::securitygroup', 'aws::ec2::networkacl', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: TEST_SECURITY_GROUP_22
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::sns::topic', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml']                                                                      |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

#### Snapshots
| Title         | Description                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT3                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                                                                     |
| type          | cloudformation                                                                                                                                                                             |
| region        |                                                                                                                                                                                            |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::scheduledaction', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingScheduledAction.yaml']                                                           |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::subnetgroup', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::elasticache::replicationgroup', 'aws::ec2::vpc', 'custom::region', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **passed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::iam::role', 'aws::dms::replicationtask', 'aws::ec2::internetgateway', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationsubnetgroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::dms::endpoint', 'aws::rds::dbcluster', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::rds::dbinstance', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::ec2::eipassociation', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::ec2::eip']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **passed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::ecs::service', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::ecs::taskdefinition', 'aws::autoscaling::launchconfiguration', 'aws::logs::loggroup', 'aws::autoscaling::autoscalinggroup', 'aws::events::rule', 'aws::applicationautoscaling::scalabletarget', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalingpolicy', 'aws::cloudwatch::alarm', 'aws::ecs::cluster', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBGuidedAutoScalingRollingUpgrade.yaml']                                                    |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::elasticloadbalancing::loadbalancer']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

#### Snapshots
| Title         | Description                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT29                                                                                                                               |
| structure     | filesystem                                                                                                                                            |
| reference     | master                                                                                                                                                |
| source        | gitConnectorAwsLabs                                                                                                                                   |
| collection    | cloudformationtemplate                                                                                                                                |
| type          | cloudformation                                                                                                                                        |
| region        |                                                                                                                                                       |
| resourceTypes | ['aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBWithLockedDownAutoScaledInstances.yaml']   |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **passed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::neptune::dbparametergroup', 'aws::neptune::dbinstance', 'aws::iam::role', 'aws::sns::subscription', 'aws::sns::topic', 'aws::ec2::securitygroup', 'aws::neptune::dbclusterparametergroup', 'aws::neptune::dbcluster', 'aws::iam::managedpolicy', 'aws::neptune::dbsubnetgroup', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbsecuritygroup', 'aws::ec2::securitygroup']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::dhcpoptions', 'aws::secretsmanager::secret', 'aws::iam::instanceprofile', 'aws::lambda::function', 'aws::ec2::securitygroup', 'aws::logs::loggroup', 'aws::ec2::vpcdhcpoptionsassociation', 'custom::adconnectorresource'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **passed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ssm::document', 'aws::ec2::instance']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::dhcpoptions', 'aws::secretsmanager::secret', 'aws::iam::instanceprofile', 'aws::directoryservice::microsoftad', 'aws::ec2::securitygroup', 'aws::ec2::vpcdhcpoptionsassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ManagedAD/templates/MANAGEDAD.cfn.yaml']                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::iam::role', 'custom::getpl', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::subnetgroup', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::elasticache::replicationgroup', 'aws::ec2::vpc', 'custom::region', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::cloudformation::waitcondition', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::instance', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EC2/ec2_with_waitcondition_template.json'] |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::efs::mounttarget', 'aws::ec2::securitygroup', 'aws::efs::filesystem', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EFS/efs_with_automount_to_ec2.json']                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **failed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-CFR-SG-023

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
| resourceTypes | ['aws::ec2::networkaclentry', 'aws::ec2::internetgateway', 'aws::ec2::eip', 'aws::ec2::routetable', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::securitygroup', 'aws::ec2::networkacl', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: TEST_SECURITY_GROUP_23
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::sns::topic', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml']                                                                      |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

#### Snapshots
| Title         | Description                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT3                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                                                                     |
| type          | cloudformation                                                                                                                                                                             |
| region        |                                                                                                                                                                                            |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::scheduledaction', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingScheduledAction.yaml']                                                           |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::subnetgroup', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::elasticache::replicationgroup', 'aws::ec2::vpc', 'custom::region', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::iam::role', 'aws::dms::replicationtask', 'aws::ec2::internetgateway', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationsubnetgroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::dms::endpoint', 'aws::rds::dbcluster', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::rds::dbinstance', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::ec2::eipassociation', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::ec2::eip']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::ecs::service', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::ecs::taskdefinition', 'aws::autoscaling::launchconfiguration', 'aws::logs::loggroup', 'aws::autoscaling::autoscalinggroup', 'aws::events::rule', 'aws::applicationautoscaling::scalabletarget', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalingpolicy', 'aws::cloudwatch::alarm', 'aws::ecs::cluster', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBGuidedAutoScalingRollingUpgrade.yaml']                                                    |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::elasticloadbalancing::loadbalancer']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

#### Snapshots
| Title         | Description                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT29                                                                                                                               |
| structure     | filesystem                                                                                                                                            |
| reference     | master                                                                                                                                                |
| source        | gitConnectorAwsLabs                                                                                                                                   |
| collection    | cloudformationtemplate                                                                                                                                |
| type          | cloudformation                                                                                                                                        |
| region        |                                                                                                                                                       |
| resourceTypes | ['aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBWithLockedDownAutoScaledInstances.yaml']   |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::neptune::dbparametergroup', 'aws::neptune::dbinstance', 'aws::iam::role', 'aws::sns::subscription', 'aws::sns::topic', 'aws::ec2::securitygroup', 'aws::neptune::dbclusterparametergroup', 'aws::neptune::dbcluster', 'aws::iam::managedpolicy', 'aws::neptune::dbsubnetgroup', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbsecuritygroup', 'aws::ec2::securitygroup']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::dhcpoptions', 'aws::secretsmanager::secret', 'aws::iam::instanceprofile', 'aws::lambda::function', 'aws::ec2::securitygroup', 'aws::logs::loggroup', 'aws::ec2::vpcdhcpoptionsassociation', 'custom::adconnectorresource'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ssm::document', 'aws::ec2::instance']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::dhcpoptions', 'aws::secretsmanager::secret', 'aws::iam::instanceprofile', 'aws::directoryservice::microsoftad', 'aws::ec2::securitygroup', 'aws::ec2::vpcdhcpoptionsassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ManagedAD/templates/MANAGEDAD.cfn.yaml']                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::iam::role', 'custom::getpl', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::subnetgroup', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::elasticache::replicationgroup', 'aws::ec2::vpc', 'custom::region', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::cloudformation::waitcondition', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::instance', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EC2/ec2_with_waitcondition_template.json'] |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::efs::mounttarget', 'aws::ec2::securitygroup', 'aws::efs::filesystem', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EFS/efs_with_automount_to_ec2.json']                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-CFR-SG-024

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
| resourceTypes | ['aws::ec2::networkaclentry', 'aws::ec2::internetgateway', 'aws::ec2::eip', 'aws::ec2::routetable', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::securitygroup', 'aws::ec2::networkacl', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: TEST_SECURITY_GROUP_24
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::sns::topic', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml']                                                                      |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

#### Snapshots
| Title         | Description                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT3                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                     |
| source        | gitConnectorAwsLabs                                                                                                                                                                        |
| collection    | cloudformationtemplate                                                                                                                                                                     |
| type          | cloudformation                                                                                                                                                                             |
| region        |                                                                                                                                                                                            |
| resourceTypes | ['aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::scheduledaction', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingScheduledAction.yaml']                                                           |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::subnetgroup', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::elasticache::replicationgroup', 'aws::ec2::vpc', 'custom::region', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::iam::role', 'aws::dms::replicationtask', 'aws::ec2::internetgateway', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationsubnetgroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::dms::endpoint', 'aws::rds::dbcluster', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::rds::dbinstance', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::ec2::eipassociation', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::ec2::eip']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::ecs::service', 'aws::iam::role', 'aws::iam::instanceprofile', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::ecs::taskdefinition', 'aws::autoscaling::launchconfiguration', 'aws::logs::loggroup', 'aws::autoscaling::autoscalinggroup', 'aws::events::rule', 'aws::applicationautoscaling::scalabletarget', 'aws::ec2::securitygroupingress', 'aws::applicationautoscaling::scalingpolicy', 'aws::cloudwatch::alarm', 'aws::ecs::cluster', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBGuidedAutoScalingRollingUpgrade.yaml']                                                    |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::elasticloadbalancing::loadbalancer']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

#### Snapshots
| Title         | Description                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT29                                                                                                                               |
| structure     | filesystem                                                                                                                                            |
| reference     | master                                                                                                                                                |
| source        | gitConnectorAwsLabs                                                                                                                                   |
| collection    | cloudformationtemplate                                                                                                                                |
| type          | cloudformation                                                                                                                                        |
| region        |                                                                                                                                                       |
| resourceTypes | ['aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBWithLockedDownAutoScaledInstances.yaml']   |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::elasticloadbalancing::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::neptune::dbparametergroup', 'aws::neptune::dbinstance', 'aws::iam::role', 'aws::sns::subscription', 'aws::sns::topic', 'aws::ec2::securitygroup', 'aws::neptune::dbclusterparametergroup', 'aws::neptune::dbcluster', 'aws::iam::managedpolicy', 'aws::neptune::dbsubnetgroup', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::rds::dbinstance', 'aws::rds::dbsecuritygroup', 'aws::ec2::securitygroup']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::dhcpoptions', 'aws::secretsmanager::secret', 'aws::iam::instanceprofile', 'aws::lambda::function', 'aws::ec2::securitygroup', 'aws::logs::loggroup', 'aws::ec2::vpcdhcpoptionsassociation', 'custom::adconnectorresource'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ec2::securitygroup', 'aws::cloudfront::distribution', 'custom::lambdaversion', 'aws::ec2::instance', 'aws::ec2::securitygroupingress', 'aws::s3::bucket', 'aws::s3::bucketpolicy', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ssm::document', 'aws::ec2::instance']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::dhcpoptions', 'aws::secretsmanager::secret', 'aws::iam::instanceprofile', 'aws::directoryservice::microsoftad', 'aws::ec2::securitygroup', 'aws::ec2::vpcdhcpoptionsassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ManagedAD/templates/MANAGEDAD.cfn.yaml']                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::iam::role', 'custom::getpl', 'aws::ec2::internetgateway', 'aws::ec2::routetable', 'aws::iam::instanceprofile', 'aws::ec2::securitygroup', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::lambda::permission', 'aws::lambda::function', 'aws::elasticache::subnetgroup', 'aws::ec2::securitygroup', 'aws::ec2::route', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::elasticache::replicationgroup', 'aws::ec2::vpc', 'custom::region', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::cloudformation::waitcondition', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::instance', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EC2/ec2_with_waitcondition_template.json'] |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::efs::mounttarget', 'aws::ec2::securitygroup', 'aws::efs::filesystem', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EFS/efs_with_automount_to_ec2.json']                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-CFR-SG-025

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
| resourceTypes | ['aws::ec2::networkaclentry', 'aws::ec2::internetgateway', 'aws::ec2::eip', 'aws::ec2::routetable', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::securitygroup', 'aws::ec2::networkacl', 'aws::ec2::subnet', 'aws::ec2::route', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpc', 'aws::ec2::vpcgatewayattachment'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: TEST_SECURITY_GROUP_25
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------

