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

## Aws Networking (Part1) Services

Source Repository: https://github.com/awslabs/aws-cloudformation-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac

## Compliance run Meta Data
| Title     | Description         |
|:----------|:--------------------|
| timestamp | 1642968990052       |
| snapshot  | master-snapshot_gen |
| container | scenario-aws-Labs   |
| test      | master-test.json    |

## Results

### Test ID - PR-AWS-CFR-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **failed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-CFR-VPC-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: PR-AWS-CFR-VPC-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CSA-CCM', 'ISO 27001', 'NIST 800', 'HITRUST', 'SOC 2', 'GDPR'] |
| service    | ['cloudformation']                                               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-CFR-VPC-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::elasticache::subnetgroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::elasticache::replicationgroup', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::lambda::permission', 'aws::ec2::route', 'aws::lambda::function', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-VPC-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CSA-CCM', 'ISO 27001', 'NIST 800', 'HITRUST', 'SOC 2', 'GDPR'] |
| service    | ['cloudformation']                                               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-CFR-VPC-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::dms::replicationsubnetgroup', 'aws::dms::endpoint', 'aws::iam::role', 'aws::rds::dbcluster', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::rds::dbinstance', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::s3::bucket', 'aws::ec2::route', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::dms::replicationtask'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-VPC-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CSA-CCM', 'ISO 27001', 'NIST 800', 'HITRUST', 'SOC 2', 'GDPR'] |
| service    | ['cloudformation']                                               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-CFR-VPC-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

- masterTestId: PR-AWS-CFR-VPC-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CSA-CCM', 'ISO 27001', 'NIST 800', 'HITRUST', 'SOC 2', 'GDPR'] |
| service    | ['cloudformation']                                               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **failed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-CFR-VPC-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::vpcendpoint', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-VPC-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CSA-CCM', 'ISO 27001', 'NIST 800', 'HITRUST', 'SOC 2', 'GDPR'] |
| service    | ['cloudformation']                                               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-CFR-VPC-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

- masterTestId: PR-AWS-CFR-VPC-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CSA-CCM', 'ISO 27001', 'NIST 800', 'HITRUST', 'SOC 2', 'GDPR'] |
| service    | ['cloudformation']                                               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **failed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-CFR-VPC-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: PR-AWS-CFR-VPC-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CSA-CCM', 'ISO 27001', 'NIST 800', 'HITRUST', 'SOC 2', 'GDPR'] |
| service    | ['cloudformation']                                               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-CFR-VPC-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::natgateway', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::lambda::function', 'aws::ec2::eip', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/LambaStaticIP/lambda-static.cfn.yaml']                                                                                                                                                   |

- masterTestId: PR-AWS-CFR-VPC-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CSA-CCM', 'ISO 27001', 'NIST 800', 'HITRUST', 'SOC 2', 'GDPR'] |
| service    | ['cloudformation']                                               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **failed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-CFR-VPC-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::route', 'aws::ec2::instance', 'custom::getpl', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: PR-AWS-CFR-VPC-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CSA-CCM', 'ISO 27001', 'NIST 800', 'HITRUST', 'SOC 2', 'GDPR'] |
| service    | ['cloudformation']                                               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-CFR-VPC-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::elasticache::subnetgroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::elasticache::replicationgroup', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::lambda::permission', 'aws::ec2::route', 'aws::lambda::function', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-VPC-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CSA-CCM', 'ISO 27001', 'NIST 800', 'HITRUST', 'SOC 2', 'GDPR'] |
| service    | ['cloudformation']                                               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-CFR-VPC-001

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
| resourceTypes | ['aws::ec2::subnetnetworkaclassociation', 'aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::internetgateway', 'aws::ec2::networkacl', 'aws::ec2::securitygroup', 'aws::ec2::networkaclentry', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::eip', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: PR-AWS-CFR-VPC-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CSA-CCM', 'ISO 27001', 'NIST 800', 'HITRUST', 'SOC 2', 'GDPR'] |
| service    | ['cloudformation']                                               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-VPC-002
Title: Ensure all EIP addresses allocated to a VPC are attached related EC2 instances\
Test Result: **passed**\
Description : Ensure that a managed Config rule for AWS Elastic IPs (EIPs) attached to EC2 instances launched inside a VPC is created. Config service tracks changes within your AWS resources configuration and saves the recorded data for security and compliance audits\

#### Test Details
- eval: data.rule.eip_instance_link
- id : PR-AWS-CFR-VPC-002

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
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::eip', 'aws::ec2::securitygroup', 'aws::ec2::eipassociation']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: PR-AWS-CFR-VPC-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-VPC-002
Title: Ensure all EIP addresses allocated to a VPC are attached related EC2 instances\
Test Result: **failed**\
Description : Ensure that a managed Config rule for AWS Elastic IPs (EIPs) attached to EC2 instances launched inside a VPC is created. Config service tracks changes within your AWS resources configuration and saves the recorded data for security and compliance audits\

#### Test Details
- eval: data.rule.eip_instance_link
- id : PR-AWS-CFR-VPC-002

#### Snapshots
| Title         | Description                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT25                                                                                                 |
| structure     | filesystem                                                                                                              |
| reference     | master                                                                                                                  |
| source        | gitConnectorAwsLabs                                                                                                     |
| collection    | cloudformationtemplate                                                                                                  |
| type          | cloudformation                                                                                                          |
| region        |                                                                                                                         |
| resourceTypes | ['aws::ec2::eip', 'aws::ec2::eipassociation', 'aws::ec2::networkinterface']                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/SingleENIwithMultipleEIPs.json'] |

- masterTestId: PR-AWS-CFR-VPC-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-VPC-002
Title: Ensure all EIP addresses allocated to a VPC are attached related EC2 instances\
Test Result: **failed**\
Description : Ensure that a managed Config rule for AWS Elastic IPs (EIPs) attached to EC2 instances launched inside a VPC is created. Config service tracks changes within your AWS resources configuration and saves the recorded data for security and compliance audits\

#### Test Details
- eval: data.rule.eip_instance_link
- id : PR-AWS-CFR-VPC-002

#### Snapshots
| Title         | Description                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT31                                                                                                                             |
| structure     | filesystem                                                                                                                                          |
| reference     | master                                                                                                                                              |
| source        | gitConnectorAwsLabs                                                                                                                                 |
| collection    | cloudformationtemplate                                                                                                                              |
| type          | cloudformation                                                                                                                                      |
| region        |                                                                                                                                                     |
| resourceTypes | ['aws::ec2::eip', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::targetgroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/NetworkLoadBalancerWithEIPs.json']          |

- masterTestId: PR-AWS-CFR-VPC-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-VPC-002
Title: Ensure all EIP addresses allocated to a VPC are attached related EC2 instances\
Test Result: **failed**\
Description : Ensure that a managed Config rule for AWS Elastic IPs (EIPs) attached to EC2 instances launched inside a VPC is created. Config service tracks changes within your AWS resources configuration and saves the recorded data for security and compliance audits\

#### Test Details
- eval: data.rule.eip_instance_link
- id : PR-AWS-CFR-VPC-002

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
| resourceTypes | ['aws::ec2::subnet', 'aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::natgateway', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::lambda::function', 'aws::ec2::eip', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/LambaStaticIP/lambda-static.cfn.yaml']                                                                                                                                                   |

- masterTestId: PR-AWS-CFR-VPC-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-VPC-002
Title: Ensure all EIP addresses allocated to a VPC are attached related EC2 instances\
Test Result: **passed**\
Description : Ensure that a managed Config rule for AWS Elastic IPs (EIPs) attached to EC2 instances launched inside a VPC is created. Config service tracks changes within your AWS resources configuration and saves the recorded data for security and compliance audits\

#### Test Details
- eval: data.rule.eip_instance_link
- id : PR-AWS-CFR-VPC-002

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
| resourceTypes | ['aws::ec2::subnetnetworkaclassociation', 'aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::internetgateway', 'aws::ec2::networkacl', 'aws::ec2::securitygroup', 'aws::ec2::networkaclentry', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::eip', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: PR-AWS-CFR-VPC-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practice']  |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-001
Title: AWS CloudFront Distributions with Field-Level Encryption not enabled\
Test Result: **failed**\
Description : This policy identifies CloudFront distributions for which field-level encryption is not enabled. Field-level encryption adds an additional layer of security along with HTTPS which protects specific data throughout system processing so that only certain applications can see it.\

#### Test Details
- eval: data.rule.cf_default_cache
- id : PR-AWS-CFR-CF-001

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
| resourceTypes | ['aws::route53::recordset', 'aws::s3::bucket', 'aws::cloudfront::distribution']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-CF-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Medium

tags
| Title      | Description                                                                           |
|:-----------|:--------------------------------------------------------------------------------------|
| cloud      | git                                                                                   |
| compliance | ['PCI-DSS', 'GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                                    |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-001
Title: AWS CloudFront Distributions with Field-Level Encryption not enabled\
Test Result: **failed**\
Description : This policy identifies CloudFront distributions for which field-level encryption is not enabled. Field-level encryption adds an additional layer of security along with HTTPS which protects specific data throughout system processing so that only certain applications can see it.\

#### Test Details
- eval: data.rule.cf_default_cache
- id : PR-AWS-CFR-CF-001

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
| resourceTypes | ['aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::lambda::function', 'custom::lambdaversion', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-CF-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Medium

tags
| Title      | Description                                                                           |
|:-----------|:--------------------------------------------------------------------------------------|
| cloud      | git                                                                                   |
| compliance | ['PCI-DSS', 'GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                                    |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-002
Title: AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication\
Test Result: **passed**\
Description : CloudFront, a content delivery network (CDN) offered by AWS, is not using a secure cipher for distribution. It is a best security practice to enforce the use of secure ciphers TLSv1.0, TLSv1.1, and/or TLSv1.2 in a CloudFront Distribution's certificate configuration. This policy scans for any deviations from this practice and returns the results.\

#### Test Details
- eval: data.rule.cf_ssl_protocol
- id : PR-AWS-CFR-CF-002

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
| resourceTypes | ['aws::route53::recordset', 'aws::s3::bucket', 'aws::cloudfront::distribution']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-CF-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-002
Title: AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication\
Test Result: **failed**\
Description : CloudFront, a content delivery network (CDN) offered by AWS, is not using a secure cipher for distribution. It is a best security practice to enforce the use of secure ciphers TLSv1.0, TLSv1.1, and/or TLSv1.2 in a CloudFront Distribution's certificate configuration. This policy scans for any deviations from this practice and returns the results.\

#### Test Details
- eval: data.rule.cf_ssl_protocol
- id : PR-AWS-CFR-CF-002

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
| resourceTypes | ['aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::lambda::function', 'custom::lambdaversion', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-CF-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-003
Title: AWS CloudFront distribution with access logging disabled\
Test Result: **failed**\
Description : This policy identifies CloudFront distributions which have access logging disabled. Enabling access log on distributions creates log files that contain detailed information about every user request that CloudFront receives. Access logs are available for web distributions. If you enable logging, you can also specify the Amazon S3 bucket that you want CloudFront to save files in.\

#### Test Details
- eval: data.rule.cf_logging
- id : PR-AWS-CFR-CF-003

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
| resourceTypes | ['aws::route53::recordset', 'aws::s3::bucket', 'aws::cloudfront::distribution']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-CF-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Medium

tags
| Title      | Description                              |
|:-----------|:-----------------------------------------|
| cloud      | git                                      |
| compliance | ['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800'] |
| service    | ['cloudformation']                       |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-003
Title: AWS CloudFront distribution with access logging disabled\
Test Result: **passed**\
Description : This policy identifies CloudFront distributions which have access logging disabled. Enabling access log on distributions creates log files that contain detailed information about every user request that CloudFront receives. Access logs are available for web distributions. If you enable logging, you can also specify the Amazon S3 bucket that you want CloudFront to save files in.\

#### Test Details
- eval: data.rule.cf_logging
- id : PR-AWS-CFR-CF-003

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
| resourceTypes | ['aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::lambda::function', 'custom::lambdaversion', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-CF-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Medium

tags
| Title      | Description                              |
|:-----------|:-----------------------------------------|
| cloud      | git                                      |
| compliance | ['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800'] |
| service    | ['cloudformation']                       |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-004
Title: AWS CloudFront origin protocol policy does not enforce HTTPS-only\
Test Result: **failed**\
Description : It is a best security practice to enforce HTTPS-only traffic between a CloudFront distribution and the origin. This policy scans for any deviations from this practice and returns the results.\

#### Test Details
- eval: data.rule.cf_https_only
- id : PR-AWS-CFR-CF-004

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
| resourceTypes | ['aws::route53::recordset', 'aws::s3::bucket', 'aws::cloudfront::distribution']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-CF-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: High

tags
| Title      | Description                                                               |
|:-----------|:--------------------------------------------------------------------------|
| cloud      | git                                                                       |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'PCI-DSS', 'GDPR'] |
| service    | ['cloudformation']                                                        |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-004
Title: AWS CloudFront origin protocol policy does not enforce HTTPS-only\
Test Result: **failed**\
Description : It is a best security practice to enforce HTTPS-only traffic between a CloudFront distribution and the origin. This policy scans for any deviations from this practice and returns the results.\

#### Test Details
- eval: data.rule.cf_https_only
- id : PR-AWS-CFR-CF-004

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
| resourceTypes | ['aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::lambda::function', 'custom::lambdaversion', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-CF-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: High

tags
| Title      | Description                                                               |
|:-----------|:--------------------------------------------------------------------------|
| cloud      | git                                                                       |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'PCI-DSS', 'GDPR'] |
| service    | ['cloudformation']                                                        |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-005
Title: AWS CloudFront viewer protocol policy is not configured with HTTPS\
Test Result: **failed**\
Description : For web distributions, you can configure CloudFront to require that viewers use HTTPS to request your objects, so connections are encrypted when CloudFront communicates with viewers.\

#### Test Details
- eval: data.rule.cf_https
- id : PR-AWS-CFR-CF-005

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
| resourceTypes | ['aws::route53::recordset', 'aws::s3::bucket', 'aws::cloudfront::distribution']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-CF-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-005
Title: AWS CloudFront viewer protocol policy is not configured with HTTPS\
Test Result: **passed**\
Description : For web distributions, you can configure CloudFront to require that viewers use HTTPS to request your objects, so connections are encrypted when CloudFront communicates with viewers.\

#### Test Details
- eval: data.rule.cf_https
- id : PR-AWS-CFR-CF-005

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
| resourceTypes | ['aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::lambda::function', 'custom::lambdaversion', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-CF-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-006
Title: AWS CloudFront web distribution that allow TLS versions 1.0 or lower\
Test Result: **passed**\
Description : This policy identifies AWS CloudFront web distributions which are configured with TLS versions for HTTPS communication between viewers and CloudFront. As a best practice, use TLSv1.1_2016 or later as the minimum protocol version in your CloudFront distribution security policies.\

#### Test Details
- eval: data.rule.cf_min_protocol
- id : PR-AWS-CFR-CF-006

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
| resourceTypes | ['aws::route53::recordset', 'aws::s3::bucket', 'aws::cloudfront::distribution']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-CF-006
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Medium

tags
| Title      | Description                                                               |
|:-----------|:--------------------------------------------------------------------------|
| cloud      | git                                                                       |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'PCI-DSS', 'GDPR'] |
| service    | ['cloudformation']                                                        |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-006
Title: AWS CloudFront web distribution that allow TLS versions 1.0 or lower\
Test Result: **failed**\
Description : This policy identifies AWS CloudFront web distributions which are configured with TLS versions for HTTPS communication between viewers and CloudFront. As a best practice, use TLSv1.1_2016 or later as the minimum protocol version in your CloudFront distribution security policies.\

#### Test Details
- eval: data.rule.cf_min_protocol
- id : PR-AWS-CFR-CF-006

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
| resourceTypes | ['aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::lambda::function', 'custom::lambdaversion', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-CF-006
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Medium

tags
| Title      | Description                                                               |
|:-----------|:--------------------------------------------------------------------------|
| cloud      | git                                                                       |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'PCI-DSS', 'GDPR'] |
| service    | ['cloudformation']                                                        |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-007
Title: AWS CloudFront web distribution with AWS Web Application Firewall (AWS WAF) service disabled\
Test Result: **failed**\
Description : This policy identifies Amazon CloudFront web distributions which have the AWS Web Application Firewall (AWS WAF) service disabled. As a best practice, enable the AWS WAF service on CloudFront web distributions to protect against application layer attacks. To block malicious requests to your Cloudfront Content Delivery Network, define the block criteria in the WAF web access control list (web ACL).\

#### Test Details
- eval: data.rule.cf_firewall
- id : PR-AWS-CFR-CF-007

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
| resourceTypes | ['aws::route53::recordset', 'aws::s3::bucket', 'aws::cloudfront::distribution']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-CF-007
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-007
Title: AWS CloudFront web distribution with AWS Web Application Firewall (AWS WAF) service disabled\
Test Result: **failed**\
Description : This policy identifies Amazon CloudFront web distributions which have the AWS Web Application Firewall (AWS WAF) service disabled. As a best practice, enable the AWS WAF service on CloudFront web distributions to protect against application layer attacks. To block malicious requests to your Cloudfront Content Delivery Network, define the block criteria in the WAF web access control list (web ACL).\

#### Test Details
- eval: data.rule.cf_firewall
- id : PR-AWS-CFR-CF-007

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
| resourceTypes | ['aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::lambda::function', 'custom::lambdaversion', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-CF-007
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['PCI-DSS', 'NIST 800'] |
| service    | ['cloudformation']      |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-008
Title: AWS CloudFront web distribution with default SSL certificate\
Test Result: **passed**\
Description : This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.\

#### Test Details
- eval: data.rule.cf_default_ssl
- id : PR-AWS-CFR-CF-008

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
| resourceTypes | ['aws::route53::recordset', 'aws::s3::bucket', 'aws::cloudfront::distribution']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-CF-008
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Medium

tags
| Title      | Description                                                               |
|:-----------|:--------------------------------------------------------------------------|
| cloud      | git                                                                       |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'PCI-DSS', 'GDPR'] |
| service    | ['cloudformation']                                                        |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-008
Title: AWS CloudFront web distribution with default SSL certificate\
Test Result: **passed**\
Description : This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.\

#### Test Details
- eval: data.rule.cf_default_ssl
- id : PR-AWS-CFR-CF-008

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
| resourceTypes | ['aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::lambda::function', 'custom::lambdaversion', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-CF-008
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Medium

tags
| Title      | Description                                                               |
|:-----------|:--------------------------------------------------------------------------|
| cloud      | git                                                                       |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'PCI-DSS', 'GDPR'] |
| service    | ['cloudformation']                                                        |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-009
Title: AWS CloudFront web distribution with geo restriction disabled\
Test Result: **failed**\
Description : This policy identifies CloudFront web distributions which have geo restriction feature disabled. Geo Restriction has the ability to block IP addresses based on Geo IP by whitelist or blacklist a country in order to allow or restrict users in specific locations from accessing web application content.\

#### Test Details
- eval: data.rule.cf_geo_restriction
- id : PR-AWS-CFR-CF-009

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
| resourceTypes | ['aws::route53::recordset', 'aws::s3::bucket', 'aws::cloudfront::distribution']                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/S3_Website_With_CloudFront_Distribution.yaml'] |

- masterTestId: PR-AWS-CFR-CF-009
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['GDPR']           |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-CF-009
Title: AWS CloudFront web distribution with geo restriction disabled\
Test Result: **failed**\
Description : This policy identifies CloudFront web distributions which have geo restriction feature disabled. Geo Restriction has the ability to block IP addresses based on Geo IP by whitelist or blacklist a country in order to allow or restrict users in specific locations from accessing web application content.\

#### Test Details
- eval: data.rule.cf_geo_restriction
- id : PR-AWS-CFR-CF-009

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
| resourceTypes | ['aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::lambda::function', 'custom::lambdaversion', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-CF-009
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/cloudfront.rego)
- severity: Low

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['GDPR']           |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::sns::topic', 'aws::autoscaling::autoscalinggroup', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::iam::role', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::iam::instanceprofile'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml']                                                                      |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::autoscaling::scheduledaction', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingScheduledAction.yaml']                                                           |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::elasticache::subnetgroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::elasticache::replicationgroup', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::lambda::permission', 'aws::ec2::route', 'aws::lambda::function', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::dms::replicationsubnetgroup', 'aws::dms::endpoint', 'aws::iam::role', 'aws::rds::dbcluster', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::rds::dbinstance', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::s3::bucket', 'aws::ec2::route', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::dms::replicationtask'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::eip', 'aws::ec2::securitygroup', 'aws::ec2::eipassociation']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::applicationautoscaling::scalingpolicy', 'aws::ecs::cluster', 'aws::logs::loggroup', 'aws::ec2::securitygroupingress', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::applicationautoscaling::scalabletarget', 'aws::autoscaling::launchconfiguration', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::events::rule', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancingv2::listenerrule', 'aws::elasticloadbalancingv2::listener', 'aws::iam::instanceprofile', 'aws::ecs::service', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::iam::role', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::iam::instanceprofile'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBGuidedAutoScalingRollingUpgrade.yaml']                                                    |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::ec2::instance', 'aws::ec2::securitygroup']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBWithLockedDownAutoScaledInstances.yaml']   |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::neptune::dbcluster', 'aws::neptune::dbclusterparametergroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::neptune::dbparametergroup', 'aws::neptune::dbsubnetgroup', 'aws::sns::subscription', 'aws::sns::topic', 'aws::iam::managedpolicy', 'aws::cloudwatch::alarm', 'aws::neptune::dbinstance'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::rds::dbsecuritygroup', 'aws::ec2::securitygroup', 'aws::rds::dbinstance']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::logs::loggroup', 'aws::secretsmanager::secret', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::dhcpoptions', 'aws::iam::instanceprofile', 'aws::lambda::function', 'custom::adconnectorresource', 'aws::ec2::vpcdhcpoptionsassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::vpcendpoint', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::lambda::function', 'custom::lambdaversion', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::securitygroup', 'aws::iam::instanceprofile', 'aws::ec2::instance', 'aws::ssm::document']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::secretsmanager::secret', 'aws::directoryservice::microsoftad', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::dhcpoptions', 'aws::iam::instanceprofile', 'aws::ec2::vpcdhcpoptionsassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ManagedAD/templates/MANAGEDAD.cfn.yaml']                                                                                    |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::route', 'aws::ec2::instance', 'custom::getpl', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::ec2::subnet', 'aws::elasticache::subnetgroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::elasticache::replicationgroup', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::lambda::permission', 'aws::ec2::route', 'aws::lambda::function', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::ec2::instance', 'aws::cloudformation::waitcondition', 'aws::ec2::securitygroup', 'aws::cloudformation::waitconditionhandle'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EC2/ec2_with_waitcondition_template.json'] |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::iam::role', 'aws::efs::filesystem', 'aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::scalingpolicy', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::iam::instanceprofile', 'aws::cloudwatch::alarm', 'aws::efs::mounttarget'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EFS/efs_with_automount_to_ec2.json']                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-CFR-SG-001

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
| resourceTypes | ['aws::ec2::subnetnetworkaclassociation', 'aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::internetgateway', 'aws::ec2::networkacl', 'aws::ec2::securitygroup', 'aws::ec2::networkaclentry', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::eip', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: PR-AWS-CFR-SG-001
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::sns::topic', 'aws::autoscaling::autoscalinggroup', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::iam::role', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::iam::instanceprofile'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml']                                                                      |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::autoscaling::scheduledaction', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingScheduledAction.yaml']                                                           |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::ec2::subnet', 'aws::elasticache::subnetgroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::elasticache::replicationgroup', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::lambda::permission', 'aws::ec2::route', 'aws::lambda::function', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::ec2::subnet', 'aws::dms::replicationsubnetgroup', 'aws::dms::endpoint', 'aws::iam::role', 'aws::rds::dbcluster', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::rds::dbinstance', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::s3::bucket', 'aws::ec2::route', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::dms::replicationtask'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::eip', 'aws::ec2::securitygroup', 'aws::ec2::eipassociation']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::applicationautoscaling::scalingpolicy', 'aws::ecs::cluster', 'aws::logs::loggroup', 'aws::ec2::securitygroupingress', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::applicationautoscaling::scalabletarget', 'aws::autoscaling::launchconfiguration', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::events::rule', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancingv2::listenerrule', 'aws::elasticloadbalancingv2::listener', 'aws::iam::instanceprofile', 'aws::ecs::service', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::iam::role', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::iam::instanceprofile'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBGuidedAutoScalingRollingUpgrade.yaml']                                                    |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::ec2::instance', 'aws::ec2::securitygroup']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBWithLockedDownAutoScaledInstances.yaml']   |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::neptune::dbcluster', 'aws::neptune::dbclusterparametergroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::neptune::dbparametergroup', 'aws::neptune::dbsubnetgroup', 'aws::sns::subscription', 'aws::sns::topic', 'aws::iam::managedpolicy', 'aws::cloudwatch::alarm', 'aws::neptune::dbinstance'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::rds::dbsecuritygroup', 'aws::ec2::securitygroup', 'aws::rds::dbinstance']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::logs::loggroup', 'aws::secretsmanager::secret', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::dhcpoptions', 'aws::iam::instanceprofile', 'aws::lambda::function', 'custom::adconnectorresource', 'aws::ec2::vpcdhcpoptionsassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::vpcendpoint', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::lambda::function', 'custom::lambdaversion', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::securitygroup', 'aws::iam::instanceprofile', 'aws::ec2::instance', 'aws::ssm::document']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::secretsmanager::secret', 'aws::directoryservice::microsoftad', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::dhcpoptions', 'aws::iam::instanceprofile', 'aws::ec2::vpcdhcpoptionsassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ManagedAD/templates/MANAGEDAD.cfn.yaml']                                                                                    |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::route', 'aws::ec2::instance', 'custom::getpl', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::ec2::subnet', 'aws::elasticache::subnetgroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::elasticache::replicationgroup', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::lambda::permission', 'aws::ec2::route', 'aws::lambda::function', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::ec2::instance', 'aws::cloudformation::waitcondition', 'aws::ec2::securitygroup', 'aws::cloudformation::waitconditionhandle'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EC2/ec2_with_waitcondition_template.json'] |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::iam::role', 'aws::efs::filesystem', 'aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::scalingpolicy', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::iam::instanceprofile', 'aws::cloudwatch::alarm', 'aws::efs::mounttarget'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EFS/efs_with_automount_to_ec2.json']                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-CFR-SG-002

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
| resourceTypes | ['aws::ec2::subnetnetworkaclassociation', 'aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::internetgateway', 'aws::ec2::networkacl', 'aws::ec2::securitygroup', 'aws::ec2::networkaclentry', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::eip', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: PR-AWS-CFR-SG-002
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::sns::topic', 'aws::autoscaling::autoscalinggroup', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::iam::role', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::iam::instanceprofile'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml']                                                                      |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::autoscaling::scheduledaction', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingScheduledAction.yaml']                                                           |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::ec2::subnet', 'aws::elasticache::subnetgroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::elasticache::replicationgroup', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::lambda::permission', 'aws::ec2::route', 'aws::lambda::function', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::ec2::subnet', 'aws::dms::replicationsubnetgroup', 'aws::dms::endpoint', 'aws::iam::role', 'aws::rds::dbcluster', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::rds::dbinstance', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::s3::bucket', 'aws::ec2::route', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::dms::replicationtask'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::eip', 'aws::ec2::securitygroup', 'aws::ec2::eipassociation']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::applicationautoscaling::scalingpolicy', 'aws::ecs::cluster', 'aws::logs::loggroup', 'aws::ec2::securitygroupingress', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::applicationautoscaling::scalabletarget', 'aws::autoscaling::launchconfiguration', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::events::rule', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancingv2::listenerrule', 'aws::elasticloadbalancingv2::listener', 'aws::iam::instanceprofile', 'aws::ecs::service', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::iam::role', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::iam::instanceprofile'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBGuidedAutoScalingRollingUpgrade.yaml']                                                    |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::ec2::instance', 'aws::ec2::securitygroup']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBWithLockedDownAutoScaledInstances.yaml']   |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::neptune::dbcluster', 'aws::neptune::dbclusterparametergroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::neptune::dbparametergroup', 'aws::neptune::dbsubnetgroup', 'aws::sns::subscription', 'aws::sns::topic', 'aws::iam::managedpolicy', 'aws::cloudwatch::alarm', 'aws::neptune::dbinstance'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::rds::dbsecuritygroup', 'aws::ec2::securitygroup', 'aws::rds::dbinstance']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::logs::loggroup', 'aws::secretsmanager::secret', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::dhcpoptions', 'aws::iam::instanceprofile', 'aws::lambda::function', 'custom::adconnectorresource', 'aws::ec2::vpcdhcpoptionsassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::vpcendpoint', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::lambda::function', 'custom::lambdaversion', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::securitygroup', 'aws::iam::instanceprofile', 'aws::ec2::instance', 'aws::ssm::document']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::secretsmanager::secret', 'aws::directoryservice::microsoftad', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::dhcpoptions', 'aws::iam::instanceprofile', 'aws::ec2::vpcdhcpoptionsassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ManagedAD/templates/MANAGEDAD.cfn.yaml']                                                                                    |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::route', 'aws::ec2::instance', 'custom::getpl', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::ec2::subnet', 'aws::elasticache::subnetgroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::elasticache::replicationgroup', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::lambda::permission', 'aws::ec2::route', 'aws::lambda::function', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::ec2::instance', 'aws::cloudformation::waitcondition', 'aws::ec2::securitygroup', 'aws::cloudformation::waitconditionhandle'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EC2/ec2_with_waitcondition_template.json'] |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::iam::role', 'aws::efs::filesystem', 'aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::scalingpolicy', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::iam::instanceprofile', 'aws::cloudwatch::alarm', 'aws::efs::mounttarget'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EFS/efs_with_automount_to_ec2.json']                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-CFR-SG-003

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
| resourceTypes | ['aws::ec2::subnetnetworkaclassociation', 'aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::internetgateway', 'aws::ec2::networkacl', 'aws::ec2::securitygroup', 'aws::ec2::networkaclentry', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::eip', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: PR-AWS-CFR-SG-003
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::sns::topic', 'aws::autoscaling::autoscalinggroup', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::iam::role', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::iam::instanceprofile'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml']                                                                      |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::autoscaling::scheduledaction', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingScheduledAction.yaml']                                                           |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::ec2::subnet', 'aws::elasticache::subnetgroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::elasticache::replicationgroup', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::lambda::permission', 'aws::ec2::route', 'aws::lambda::function', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::ec2::subnet', 'aws::dms::replicationsubnetgroup', 'aws::dms::endpoint', 'aws::iam::role', 'aws::rds::dbcluster', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::rds::dbinstance', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::s3::bucket', 'aws::ec2::route', 'aws::rds::dbsubnetgroup', 'aws::dms::replicationinstance', 'aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::dms::replicationtask'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::ec2::instance', 'aws::ec2::eip', 'aws::ec2::securitygroup', 'aws::ec2::eipassociation']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::applicationautoscaling::scalingpolicy', 'aws::ecs::cluster', 'aws::logs::loggroup', 'aws::ec2::securitygroupingress', 'aws::ecs::taskdefinition', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::applicationautoscaling::scalabletarget', 'aws::autoscaling::launchconfiguration', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::events::rule', 'aws::autoscaling::autoscalinggroup', 'aws::elasticloadbalancingv2::listenerrule', 'aws::elasticloadbalancingv2::listener', 'aws::iam::instanceprofile', 'aws::ecs::service', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::iam::role', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::iam::instanceprofile'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBGuidedAutoScalingRollingUpgrade.yaml']                                                    |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::ec2::instance', 'aws::ec2::securitygroup']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBWithLockedDownAutoScaledInstances.yaml']   |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::s3::bucket', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::neptune::dbcluster', 'aws::neptune::dbclusterparametergroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::neptune::dbparametergroup', 'aws::neptune::dbsubnetgroup', 'aws::sns::subscription', 'aws::sns::topic', 'aws::iam::managedpolicy', 'aws::cloudwatch::alarm', 'aws::neptune::dbinstance'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::rds::dbsecuritygroup', 'aws::ec2::securitygroup', 'aws::rds::dbinstance']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::logs::loggroup', 'aws::secretsmanager::secret', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::dhcpoptions', 'aws::iam::instanceprofile', 'aws::lambda::function', 'custom::adconnectorresource', 'aws::ec2::vpcdhcpoptionsassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::vpcendpoint', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::internetgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::targetgroup', 'aws::iam::role', 'aws::ec2::instance', 'aws::ec2::securitygroup', 'aws::kms::alias', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::ec2::securitygroupegress', 'aws::kms::key', 'aws::s3::bucket', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::listenerrule', 'aws::cloudfront::distribution', 'aws::lambda::function', 'custom::lambdaversion', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::iam::role', 'aws::ec2::securitygroup', 'aws::iam::instanceprofile', 'aws::ec2::instance', 'aws::ssm::document']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::secretsmanager::secret', 'aws::directoryservice::microsoftad', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::dhcpoptions', 'aws::iam::instanceprofile', 'aws::ec2::vpcdhcpoptionsassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ManagedAD/templates/MANAGEDAD.cfn.yaml']                                                                                    |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::iam::role', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::iam::instanceprofile', 'aws::ec2::route', 'aws::ec2::instance', 'custom::getpl', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::ec2::subnet', 'aws::elasticache::subnetgroup', 'aws::iam::role', 'aws::ec2::securitygroup', 'aws::ec2::internetgateway', 'aws::elasticache::parametergroup', 'aws::elasticache::replicationgroup', 'aws::ec2::vpcgatewayattachment', 'custom::region', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::lambda::permission', 'aws::ec2::route', 'aws::lambda::function', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::ec2::instance', 'aws::cloudformation::waitcondition', 'aws::ec2::securitygroup', 'aws::cloudformation::waitconditionhandle'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EC2/ec2_with_waitcondition_template.json'] |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::iam::role', 'aws::efs::filesystem', 'aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::scalingpolicy', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::iam::instanceprofile', 'aws::cloudwatch::alarm', 'aws::efs::mounttarget'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EFS/efs_with_automount_to_ec2.json']                                                                                                                                                                                      |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-CFR-SG-004

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
| resourceTypes | ['aws::ec2::subnetnetworkaclassociation', 'aws::ec2::subnet', 'aws::cloudformation::waitcondition', 'aws::ec2::internetgateway', 'aws::ec2::networkacl', 'aws::ec2::securitygroup', 'aws::ec2::networkaclentry', 'aws::ec2::vpcgatewayattachment', 'aws::cloudformation::waitconditionhandle', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::eip', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: PR-AWS-CFR-SG-004
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-005
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1434)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1434) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1434) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1434
- id : PR-AWS-CFR-SG-005

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
| resourceTypes | ['aws::autoscaling::scalingpolicy', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::sns::topic', 'aws::autoscaling::autoscalinggroup', 'aws::cloudwatch::alarm'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

- masterTestId: PR-AWS-CFR-SG-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-005
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1434)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1434) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1434) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1434
- id : PR-AWS-CFR-SG-005

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
| resourceTypes | ['aws::iam::role', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup', 'aws::iam::instanceprofile'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml']                                                                      |

- masterTestId: PR-AWS-CFR-SG-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-005
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1434)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1434) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1434) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1434
- id : PR-AWS-CFR-SG-005

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
| resourceTypes | ['aws::autoscaling::scheduledaction', 'aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::autoscaling::autoscalinggroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingScheduledAction.yaml']                                                           |

- masterTestId: PR-AWS-CFR-SG-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------


### Test ID - PR-AWS-CFR-SG-005
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1434)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1434) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1434) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1434
- id : PR-AWS-CFR-SG-005

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
| resourceTypes | ['aws::ec2::subnet', 'aws::ec2::internetgateway', 'aws::ec2::securitygroup', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::vpc', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::route', 'aws::ec2::instance', 'aws::ec2::routetable'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: PR-AWS-CFR-SG-005
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['cloudformation']               |
----------------------------------------------------------------

