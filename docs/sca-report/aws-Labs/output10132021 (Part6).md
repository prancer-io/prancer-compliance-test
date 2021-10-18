# Automated Vulnerability Scan result and Static Code Analysis for Aws Labs files


## Aws Labs Services (Part 6)

Source Repository: https://github.com/awslabs/aws-cloudformation-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac

## Compliance run Meta Data
| Title     | Description         |
|:----------|:--------------------|
| timestamp | 1634201533099       |
| snapshot  | master-snapshot_gen |
| container | scenario-aws-lab    |
| test      | master-test.json    |

## Results

### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/centos.template'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/debian.template'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/redhat.template'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/suse.template'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/ubuntu.template'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/amazon_linux.template'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/centos.template'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/debian.template'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/redhat.template'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/suse.template'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/ubuntu.template'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::iam::instanceprofile', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::ec2::vpcendpoint', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::iam::instanceprofile', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroup', 'aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::s3::bucket', 'aws::ec2::instance', 'aws::cloudfront::distribution', 'aws::iam::role', 'aws::lambda::function', 'custom::lambdaversion', 'aws::kms::key', 'aws::ec2::securitygroupegress', 'aws::kms::alias', 'aws::elasticloadbalancingv2::listenerrule', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::ec2::instance', 'aws::iam::role', 'aws::ssm::document', 'aws::ec2::securitygroup']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/HelperNonAmaznAmi/RHEL7_cfn-hup.template'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/HelperNonAmaznAmi/ubuntu16.04LTS_cfn-hup.template'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::vpcdhcpoptionsassociation', 'aws::ec2::dhcpoptions', 'aws::iam::instanceprofile', 'aws::secretsmanager::secret', 'aws::iam::role', 'aws::directoryservice::microsoftad', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ManagedAD/templates/MANAGEDAD.cfn.yaml']                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/RHEL7_cfn-hup.cfn.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/RHEL8_cfn-hup.cfn.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/ubuntu16.04LTS_cfn-hup.cfn.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/ubuntu18.04LTS_cfn-hup.cfn.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/ubuntu20.04LTS_cfn-hup.cfn.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::iam::instanceprofile', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'custom::getpl', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::elasticache::replicationgroup', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::elasticache::subnetgroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::lambda::function', 'custom::region', 'aws::lambda::permission', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/WordPress_Single_Instance.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::cloudformation::waitconditionhandle', 'aws::ec2::securitygroup', 'aws::cloudformation::waitcondition', 'aws::ec2::instance'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EC2/ec2_with_waitcondition_template.json'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::autoscaling::scalingpolicy', 'aws::efs::filesystem', 'aws::cloudwatch::alarm', 'aws::iam::instanceprofile', 'aws::elasticloadbalancing::loadbalancer', 'aws::iam::role', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::efs::mounttarget', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EFS/efs_with_automount_to_ec2.json']                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0174-CFR
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-0174-CFR

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
| resourceTypes | ['aws::ec2::eip', 'aws::ec2::networkacl', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::ec2::networkaclentry', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::autoscaling::scalingpolicy', 'aws::sns::topic', 'aws::cloudwatch::alarm', 'aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::elasticloadbalancing::loadbalancer', 'aws::iam::role', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml']                                                                      |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::autoscaling::scheduledaction', 'aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingScheduledAction.yaml']                                                           |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::elasticache::replicationgroup', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::elasticache::subnetgroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::lambda::function', 'custom::region', 'aws::lambda::permission', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::rds::dbsubnetgroup', 'aws::ec2::subnetroutetableassociation', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::dms::replicationsubnetgroup', 'aws::dms::endpoint', 'aws::dms::replicationtask', 'aws::rds::dbcluster', 'aws::ec2::route', 'aws::rds::dbinstance', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2InstanceWithSecurityGroupSample.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2_Instance_With_Ephemeral_Drives.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::eipassociation', 'aws::ec2::eip', 'aws::ec2::securitygroup', 'aws::ec2::instance']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::events::rule', 'aws::ecs::service', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::cluster', 'aws::cloudwatch::alarm', 'aws::elasticloadbalancingv2::listener', 'aws::iam::instanceprofile', 'aws::iam::role', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::taskdefinition', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::elasticloadbalancing::loadbalancer', 'aws::iam::role', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBGuidedAutoScalingRollingUpgrade.yaml']                                                    |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::ec2::instance']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBWithLockedDownAutoScaledInstances.yaml']   |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::s3::bucket', 'aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::neptune::dbsubnetgroup', 'aws::sns::topic', 'aws::iam::managedpolicy', 'aws::neptune::dbcluster', 'aws::neptune::dbclusterparametergroup', 'aws::cloudwatch::alarm', 'aws::iam::role', 'aws::neptune::dbinstance', 'aws::sns::subscription', 'aws::neptune::dbparametergroup', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::rds::dbsecuritygroup', 'aws::rds::dbinstance', 'aws::ec2::securitygroup']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::logs::loggroup', 'custom::adconnectorresource', 'aws::ec2::vpcdhcpoptionsassociation', 'aws::ec2::dhcpoptions', 'aws::iam::instanceprofile', 'aws::secretsmanager::secret', 'aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/amazon_linux.template'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/centos.template'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/debian.template'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/redhat.template'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/suse.template'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/ubuntu.template'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/amazon_linux.template'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/centos.template'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/debian.template'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/redhat.template'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/suse.template'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/ubuntu.template'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::iam::instanceprofile', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::ec2::vpcendpoint', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::iam::instanceprofile', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroup', 'aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::s3::bucket', 'aws::ec2::instance', 'aws::cloudfront::distribution', 'aws::iam::role', 'aws::lambda::function', 'custom::lambdaversion', 'aws::kms::key', 'aws::ec2::securitygroupegress', 'aws::kms::alias', 'aws::elasticloadbalancingv2::listenerrule', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::ec2::instance', 'aws::iam::role', 'aws::ssm::document', 'aws::ec2::securitygroup']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/HelperNonAmaznAmi/RHEL7_cfn-hup.template'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/HelperNonAmaznAmi/ubuntu16.04LTS_cfn-hup.template'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::vpcdhcpoptionsassociation', 'aws::ec2::dhcpoptions', 'aws::iam::instanceprofile', 'aws::secretsmanager::secret', 'aws::iam::role', 'aws::directoryservice::microsoftad', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ManagedAD/templates/MANAGEDAD.cfn.yaml']                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/RHEL7_cfn-hup.cfn.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/RHEL8_cfn-hup.cfn.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/ubuntu16.04LTS_cfn-hup.cfn.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/ubuntu18.04LTS_cfn-hup.cfn.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/ubuntu20.04LTS_cfn-hup.cfn.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::iam::instanceprofile', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'custom::getpl', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::elasticache::replicationgroup', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::elasticache::subnetgroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::lambda::function', 'custom::region', 'aws::lambda::permission', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/WordPress_Single_Instance.yaml'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::cloudformation::waitconditionhandle', 'aws::ec2::securitygroup', 'aws::cloudformation::waitcondition', 'aws::ec2::instance'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EC2/ec2_with_waitcondition_template.json'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::autoscaling::scalingpolicy', 'aws::efs::filesystem', 'aws::cloudwatch::alarm', 'aws::iam::instanceprofile', 'aws::elasticloadbalancing::loadbalancer', 'aws::iam::role', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::efs::mounttarget', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/EFS/efs_with_automount_to_ec2.json']                                                                                                                                                                                      |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0035-CFR
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-0035-CFR

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
| resourceTypes | ['aws::ec2::eip', 'aws::ec2::networkacl', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::ec2::networkaclentry', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['cloudformation']                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::autoscaling::scalingpolicy', 'aws::sns::topic', 'aws::cloudwatch::alarm', 'aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::elasticloadbalancing::loadbalancer', 'aws::iam::role', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml']                                                                      |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::autoscaling::scheduledaction', 'aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingScheduledAction.yaml']                                                           |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::elasticache::replicationgroup', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::elasticache::subnetgroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::lambda::function', 'custom::region', 'aws::lambda::permission', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::rds::dbsubnetgroup', 'aws::ec2::subnetroutetableassociation', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::dms::replicationsubnetgroup', 'aws::dms::endpoint', 'aws::dms::replicationtask', 'aws::rds::dbcluster', 'aws::ec2::route', 'aws::rds::dbinstance', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2InstanceWithSecurityGroupSample.yaml'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2_Instance_With_Ephemeral_Drives.yaml'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::eipassociation', 'aws::ec2::eip', 'aws::ec2::securitygroup', 'aws::ec2::instance']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::logs::loggroup', 'aws::applicationautoscaling::scalingpolicy', 'aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::events::rule', 'aws::ecs::service', 'aws::applicationautoscaling::scalabletarget', 'aws::ecs::cluster', 'aws::cloudwatch::alarm', 'aws::elasticloadbalancingv2::listener', 'aws::iam::instanceprofile', 'aws::iam::role', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::elasticloadbalancingv2::listenerrule', 'aws::ecs::taskdefinition', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ECS/ECS_Schedule_Example.template']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::elasticloadbalancing::loadbalancer', 'aws::iam::role', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBGuidedAutoScalingRollingUpgrade.yaml']                                                    |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::ec2::instance']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::autoscaling::launchconfiguration', 'aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBWithLockedDownAutoScaledInstances.yaml']   |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::s3::bucket', 'aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::neptune::dbsubnetgroup', 'aws::sns::topic', 'aws::iam::managedpolicy', 'aws::neptune::dbcluster', 'aws::neptune::dbclusterparametergroup', 'aws::cloudwatch::alarm', 'aws::iam::role', 'aws::neptune::dbinstance', 'aws::sns::subscription', 'aws::neptune::dbparametergroup', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::rds::dbsecuritygroup', 'aws::rds::dbinstance', 'aws::ec2::securitygroup']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::logs::loggroup', 'custom::adconnectorresource', 'aws::ec2::vpcdhcpoptionsassociation', 'aws::ec2::dhcpoptions', 'aws::iam::instanceprofile', 'aws::secretsmanager::secret', 'aws::iam::role', 'aws::lambda::function', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/ADConnector/templates/ADCONNECTOR.cfn.yaml']                                                                                                                         |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/amazon_linux.template'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/centos.template'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/debian.template'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/redhat.template'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/suse.template'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/ubuntu.template'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/amazon_linux.template'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/centos.template'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/debian.template'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/redhat.template'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/suse.template'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/ubuntu.template'] |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::iam::instanceprofile', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::ec2::vpcendpoint', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::iam::instanceprofile', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroup', 'aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::s3::bucket', 'aws::ec2::instance', 'aws::cloudfront::distribution', 'aws::iam::role', 'aws::lambda::function', 'custom::lambdaversion', 'aws::kms::key', 'aws::ec2::securitygroupegress', 'aws::kms::alias', 'aws::elasticloadbalancingv2::listenerrule', 'aws::s3::bucketpolicy'] |
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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::ec2::instance', 'aws::iam::role', 'aws::ssm::document', 'aws::ec2::securitygroup']   |
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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                              |
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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                       |
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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::vpcdhcpoptionsassociation', 'aws::ec2::dhcpoptions', 'aws::iam::instanceprofile', 'aws::secretsmanager::secret', 'aws::iam::role', 'aws::directoryservice::microsoftad', 'aws::ec2::securitygroup'] |
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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                             |
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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                             |
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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                      |
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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                      |
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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                      |
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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::iam::instanceprofile', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'custom::getpl', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::elasticache::replicationgroup', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::elasticache::subnetgroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::lambda::function', 'custom::region', 'aws::lambda::permission', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                    |
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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::cloudformation::waitconditionhandle', 'aws::ec2::securitygroup', 'aws::cloudformation::waitcondition', 'aws::ec2::instance'] |
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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::autoscaling::scalingpolicy', 'aws::efs::filesystem', 'aws::cloudwatch::alarm', 'aws::iam::instanceprofile', 'aws::elasticloadbalancing::loadbalancer', 'aws::iam::role', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::efs::mounttarget', 'aws::ec2::securitygroup'] |
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


### Test ID - PR-AWS-0178-CFR
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-0178-CFR

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
| resourceTypes | ['aws::ec2::eip', 'aws::ec2::networkacl', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::ec2::networkaclentry', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
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


### Test ID - PR-AWS-0152-CFR
Title: AWS SNS subscription is not configured with HTTPS\
Test Result: **passed**\
Description : This policy identifies SNS subscriptions using HTTP instead of HTTPS as the delivery protocol in order to enforce SSL encryption for all subscription requests. It is strongly recommended use only HTTPS-based subscriptions by implementing secure SNS topic policies.\

#### Test Details
- eval: data.rule.sns_protocol
- id : PR-AWS-0152-CFR

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
| resourceTypes | ['aws::neptune::dbsubnetgroup', 'aws::sns::topic', 'aws::iam::managedpolicy', 'aws::neptune::dbcluster', 'aws::neptune::dbclusterparametergroup', 'aws::cloudwatch::alarm', 'aws::iam::role', 'aws::neptune::dbinstance', 'aws::sns::subscription', 'aws::neptune::dbparametergroup', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: TEST_SNS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0152-CFR
Title: AWS SNS subscription is not configured with HTTPS\
Test Result: **passed**\
Description : This policy identifies SNS subscriptions using HTTP instead of HTTPS as the delivery protocol in order to enforce SSL encryption for all subscription requests. It is strongly recommended use only HTTPS-based subscriptions by implementing secure SNS topic policies.\

#### Test Details
- eval: data.rule.sns_protocol
- id : PR-AWS-0152-CFR

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

- masterTestId: TEST_SNS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0153-CFR
Title: AWS SNS topic encrypted using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.\

#### Test Details
- eval: data.rule.sns_encrypt_key
- id : PR-AWS-0153-CFR

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
| resourceTypes | ['aws::autoscaling::scalingpolicy', 'aws::sns::topic', 'aws::cloudwatch::alarm', 'aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

- masterTestId: TEST_SNS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0153-CFR
Title: AWS SNS topic encrypted using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.\

#### Test Details
- eval: data.rule.sns_encrypt_key
- id : PR-AWS-0153-CFR

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
| resourceTypes | ['aws::config::configurationrecorder', 'aws::sns::topic', 'aws::sns::topicpolicy', 'aws::config::deliverychannel', 'aws::config::configrule', 'aws::s3::bucket', 'aws::iam::role', 'aws::lambda::function', 'aws::lambda::permission', 'aws::ec2::volume'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: TEST_SNS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0153-CFR
Title: AWS SNS topic encrypted using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.\

#### Test Details
- eval: data.rule.sns_encrypt_key
- id : PR-AWS-0153-CFR

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
| resourceTypes | ['aws::neptune::dbsubnetgroup', 'aws::sns::topic', 'aws::iam::managedpolicy', 'aws::neptune::dbcluster', 'aws::neptune::dbclusterparametergroup', 'aws::cloudwatch::alarm', 'aws::iam::role', 'aws::neptune::dbinstance', 'aws::sns::subscription', 'aws::neptune::dbparametergroup', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: TEST_SNS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0153-CFR
Title: AWS SNS topic encrypted using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.\

#### Test Details
- eval: data.rule.sns_encrypt_key
- id : PR-AWS-0153-CFR

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

- masterTestId: TEST_SNS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0153-CFR
Title: AWS SNS topic encrypted using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.\

#### Test Details
- eval: data.rule.sns_encrypt_key
- id : PR-AWS-0153-CFR

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
| resourceTypes | ['aws::logs::loggroup', 'aws::sns::topic', 'custom::directorysettingsresource', 'aws::iam::role', 'aws::lambda::function']                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/DirectoryServiceSettings/templates/DIRECTORY_SETTINGS.cfn.yaml'] |

- masterTestId: TEST_SNS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0154-CFR
Title: AWS SNS topic with server-side encryption disabled\
Test Result: **failed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.\

#### Test Details
- eval: data.rule.sns_encrypt
- id : PR-AWS-0154-CFR

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
| resourceTypes | ['aws::autoscaling::scalingpolicy', 'aws::sns::topic', 'aws::cloudwatch::alarm', 'aws::elasticloadbalancing::loadbalancer', 'aws::autoscaling::autoscalinggroup', 'aws::autoscaling::launchconfiguration', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/AutoScaling/AutoScalingMultiAZWithNotifications.yaml']                                                                                             |

- masterTestId: TEST_SNS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0154-CFR
Title: AWS SNS topic with server-side encryption disabled\
Test Result: **failed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.\

#### Test Details
- eval: data.rule.sns_encrypt
- id : PR-AWS-0154-CFR

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
| resourceTypes | ['aws::config::configurationrecorder', 'aws::sns::topic', 'aws::sns::topicpolicy', 'aws::config::deliverychannel', 'aws::config::configrule', 'aws::s3::bucket', 'aws::iam::role', 'aws::lambda::function', 'aws::lambda::permission', 'aws::ec2::volume'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: TEST_SNS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0154-CFR
Title: AWS SNS topic with server-side encryption disabled\
Test Result: **failed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.\

#### Test Details
- eval: data.rule.sns_encrypt
- id : PR-AWS-0154-CFR

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
| resourceTypes | ['aws::neptune::dbsubnetgroup', 'aws::sns::topic', 'aws::iam::managedpolicy', 'aws::neptune::dbcluster', 'aws::neptune::dbclusterparametergroup', 'aws::cloudwatch::alarm', 'aws::iam::role', 'aws::neptune::dbinstance', 'aws::sns::subscription', 'aws::neptune::dbparametergroup', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/NeptuneDB/Neptune.yaml']                                                                                                                                                                                                      |

- masterTestId: TEST_SNS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0154-CFR
Title: AWS SNS topic with server-side encryption disabled\
Test Result: **failed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.\

#### Test Details
- eval: data.rule.sns_encrypt
- id : PR-AWS-0154-CFR

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

- masterTestId: TEST_SNS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0154-CFR
Title: AWS SNS topic with server-side encryption disabled\
Test Result: **passed**\
Description : This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.\

#### Test Details
- eval: data.rule.sns_encrypt
- id : PR-AWS-0154-CFR

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
| resourceTypes | ['aws::logs::loggroup', 'aws::sns::topic', 'custom::directorysettingsresource', 'aws::iam::role', 'aws::lambda::function']                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/DirectoryServiceSettings/templates/DIRECTORY_SETTINGS.cfn.yaml'] |

- masterTestId: TEST_SNS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0155-CFR
Title: AWS SQS does not have a dead letter queue configured\
Test Result: **failed**\
Description : This policy identifies AWS Simple Queue Services (SQS) which does not have dead letter queue configured. Dead letter queues are useful for debugging your application or messaging system because they let you isolate problematic messages to determine why their processing doesn't succeed.\

#### Test Details
- eval: data.rule.sqs_deadletter
- id : PR-AWS-0155-CFR

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

- masterTestId: TEST_SQS_1
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


### Test ID - PR-AWS-0155-CFR
Title: AWS SQS does not have a dead letter queue configured\
Test Result: **failed**\
Description : This policy identifies AWS Simple Queue Services (SQS) which does not have dead letter queue configured. Dead letter queues are useful for debugging your application or messaging system because they let you isolate problematic messages to determine why their processing doesn't succeed.\

#### Test Details
- eval: data.rule.sqs_deadletter
- id : PR-AWS-0155-CFR

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

- masterTestId: TEST_SQS_1
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


### Test ID - PR-AWS-0155-CFR
Title: AWS SQS does not have a dead letter queue configured\
Test Result: **failed**\
Description : This policy identifies AWS Simple Queue Services (SQS) which does not have dead letter queue configured. Dead letter queues are useful for debugging your application or messaging system because they let you isolate problematic messages to determine why their processing doesn't succeed.\

#### Test Details
- eval: data.rule.sqs_deadletter
- id : PR-AWS-0155-CFR

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
| resourceTypes | ['aws::dynamodb::table', 'aws::sqs::queue']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/TestResources/events.yaml'] |

- masterTestId: TEST_SQS_1
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


### Test ID - PR-AWS-0156-CFR
Title: AWS SQS queue encryption using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.\

#### Test Details
- eval: data.rule.sqs_encrypt_key
- id : PR-AWS-0156-CFR

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

- masterTestId: TEST_SQS_2
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


### Test ID - PR-AWS-0156-CFR
Title: AWS SQS queue encryption using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.\

#### Test Details
- eval: data.rule.sqs_encrypt_key
- id : PR-AWS-0156-CFR

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

- masterTestId: TEST_SQS_2
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


### Test ID - PR-AWS-0156-CFR
Title: AWS SQS queue encryption using default KMS key instead of CMK\
Test Result: **passed**\
Description : This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.\

#### Test Details
- eval: data.rule.sqs_encrypt_key
- id : PR-AWS-0156-CFR

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
| resourceTypes | ['aws::dynamodb::table', 'aws::sqs::queue']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/TestResources/events.yaml'] |

- masterTestId: TEST_SQS_2
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


### Test ID - PR-AWS-0157-CFR
Title: AWS SQS server side encryption not enabled\
Test Result: **failed**\
Description : SSE lets you transmit sensitive data in encrypted queues. SSE protects the contents of messages in Amazon SQS queues using keys managed in the AWS Key Management Service (AWS KMS). SSE encrypts messages as soon as Amazon SQS receives them. The messages are stored in encrypted form and Amazon SQS decrypts messages only when they are sent to an authorized consumer._x000D__x000D_SQS SSE and the AWS KMS security standards can help you meet encryption-related compliance requirements.\

#### Test Details
- eval: data.rule.sqs_encrypt
- id : PR-AWS-0157-CFR

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

- masterTestId: TEST_SQS_3
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


### Test ID - PR-AWS-0157-CFR
Title: AWS SQS server side encryption not enabled\
Test Result: **failed**\
Description : SSE lets you transmit sensitive data in encrypted queues. SSE protects the contents of messages in Amazon SQS queues using keys managed in the AWS Key Management Service (AWS KMS). SSE encrypts messages as soon as Amazon SQS receives them. The messages are stored in encrypted form and Amazon SQS decrypts messages only when they are sent to an authorized consumer._x000D__x000D_SQS SSE and the AWS KMS security standards can help you meet encryption-related compliance requirements.\

#### Test Details
- eval: data.rule.sqs_encrypt
- id : PR-AWS-0157-CFR

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

- masterTestId: TEST_SQS_3
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


### Test ID - PR-AWS-0157-CFR
Title: AWS SQS server side encryption not enabled\
Test Result: **failed**\
Description : SSE lets you transmit sensitive data in encrypted queues. SSE protects the contents of messages in Amazon SQS queues using keys managed in the AWS Key Management Service (AWS KMS). SSE encrypts messages as soon as Amazon SQS receives them. The messages are stored in encrypted form and Amazon SQS decrypts messages only when they are sent to an authorized consumer._x000D__x000D_SQS SSE and the AWS KMS security standards can help you meet encryption-related compliance requirements.\

#### Test Details
- eval: data.rule.sqs_encrypt
- id : PR-AWS-0157-CFR

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
| resourceTypes | ['aws::dynamodb::table', 'aws::sqs::queue']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/TestResources/events.yaml'] |

- masterTestId: TEST_SQS_3
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


### Test ID - PR-AWS-0184-CFR
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **failed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-0184-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: TEST_VPC
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-0184-CFR
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-0184-CFR

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
| resourceTypes | ['aws::elasticache::replicationgroup', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::elasticache::subnetgroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::lambda::function', 'custom::region', 'aws::lambda::permission', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                      |

- masterTestId: TEST_VPC
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-0184-CFR
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-0184-CFR

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
| resourceTypes | ['aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::rds::dbsubnetgroup', 'aws::ec2::subnetroutetableassociation', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::dms::replicationsubnetgroup', 'aws::dms::endpoint', 'aws::dms::replicationtask', 'aws::rds::dbcluster', 'aws::ec2::route', 'aws::rds::dbinstance', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_VPC
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-0184-CFR
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-0184-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

- masterTestId: TEST_VPC
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-0184-CFR
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **failed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-0184-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::iam::instanceprofile', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::ec2::vpcendpoint', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: TEST_VPC
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-0184-CFR
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-0184-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

- masterTestId: TEST_VPC
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-0184-CFR
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **failed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-0184-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::iam::instanceprofile', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: TEST_VPC
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-0184-CFR
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-0184-CFR

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
| resourceTypes | ['aws::ec2::eip', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::natgateway', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::lambda::function', 'aws::ec2::route'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/LambaStaticIP/lambda-static.cfn.yaml']                                                                                                                                                   |

- masterTestId: TEST_VPC
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-0184-CFR
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **failed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-0184-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::iam::instanceprofile', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'custom::getpl', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                                   |

- masterTestId: TEST_VPC
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-0184-CFR
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-0184-CFR

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
| resourceTypes | ['aws::elasticache::replicationgroup', 'aws::elasticache::parametergroup', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::elasticache::subnetgroup', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::lambda::function', 'custom::region', 'aws::lambda::permission', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/Elasticache-snapshot.template']                                                                                                                                                                                                                                                                                                    |

- masterTestId: TEST_VPC
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-0184-CFR
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-0184-CFR

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
| resourceTypes | ['aws::ec2::eip', 'aws::ec2::networkacl', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::ec2::networkaclentry', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: TEST_VPC
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['cloudformation']                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-0113-CFR
Title: AWS Network ACLs with Inbound rule to allow All ICMP IPv4\
Test Result: **passed**\
Description : This policy identifies ACLs which allows traffic on all ICMP IPv4 protocol. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Inbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACL to restrict traffic on authorized protocols.\

#### Test Details
- eval: data.rule.acl_all_icmp_ipv4
- id : PR-AWS-0113-CFR

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
| resourceTypes | ['aws::ec2::eip', 'aws::ec2::networkacl', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::ec2::networkaclentry', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: TEST_NETWORKACL_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2networkacl.rego)
- severity: Medium

tags
| Title      | Description                         |
|:-----------|:------------------------------------|
| cloud      | git                                 |
| compliance | []                                  |
| service    | ['ec2networkacl', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0114-CFR
Title: AWS Network ACLs with Inbound rule to allow All ICMP IPv6\
Test Result: **passed**\
Description : This policy identifies ACLs which allows traffic on all ICMP IPv6 protocol. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Inbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACL to restrict traffic on authorized protocols.\

#### Test Details
- eval: data.rule.acl_all_icmp_ipv6
- id : PR-AWS-0114-CFR

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
| resourceTypes | ['aws::ec2::eip', 'aws::ec2::networkacl', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::ec2::networkaclentry', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: TEST_NETWORKACL_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2networkacl.rego)
- severity: Medium

tags
| Title      | Description                         |
|:-----------|:------------------------------------|
| cloud      | git                                 |
| compliance | []                                  |
| service    | ['ec2networkacl', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0115-CFR
Title: AWS Network ACLs with Inbound rule to allow All Traffic\
Test Result: **passed**\
Description : This policy identifies ACLs which allows traffic on all protocols. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Inbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACLs to restrict traffic on authorized protocols.\

#### Test Details
- eval: data.rule.acl_all_traffic
- id : PR-AWS-0115-CFR

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
| resourceTypes | ['aws::ec2::eip', 'aws::ec2::networkacl', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::ec2::networkaclentry', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: TEST_NETWORKACL_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2networkacl.rego)
- severity: Medium

tags
| Title      | Description                         |
|:-----------|:------------------------------------|
| cloud      | git                                 |
| compliance | []                                  |
| service    | ['ec2networkacl', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0116-CFR
Title: AWS Network ACLs with Outbound rule to allow All ICMP IPv4\
Test Result: **passed**\
Description : This policy identifies ACLs which allows traffic on all protocol. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Outbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACL to restrict traffic on authorized protocols.\

#### Test Details
- eval: data.rule.acl_all_icmp_ipv4_out
- id : PR-AWS-0116-CFR

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
| resourceTypes | ['aws::ec2::eip', 'aws::ec2::networkacl', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::ec2::networkaclentry', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: TEST_NETWORKACL_4
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2networkacl.rego)
- severity: Medium

tags
| Title      | Description                         |
|:-----------|:------------------------------------|
| cloud      | git                                 |
| compliance | []                                  |
| service    | ['ec2networkacl', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0117-CFR
Title: AWS Network ACLs with Outbound rule to allow All ICMP IPv6\
Test Result: **passed**\
Description : This policy identifies ACLs which allows traffic on all protocol. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Outbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACL to restrict traffic on authorized protocols.\

#### Test Details
- eval: data.rule.acl_all_icmp_ipv6_out
- id : PR-AWS-0117-CFR

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
| resourceTypes | ['aws::ec2::eip', 'aws::ec2::networkacl', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::ec2::networkaclentry', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: TEST_NETWORKACL_5
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2networkacl.rego)
- severity: Medium

tags
| Title      | Description                         |
|:-----------|:------------------------------------|
| cloud      | git                                 |
| compliance | []                                  |
| service    | ['ec2networkacl', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0118-CFR
Title: AWS Network ACLs with Outbound rule to allow All Traffic\
Test Result: **passed**\
Description : This policy identifies ACLs which allows traffic on all protocols. A network access control list (ACL) is an optional layer of security for your VPC that acts as a firewall for controlling traffic in and out of one or more subnets. By default, ACL allows all inbound and outbound IPv4 traffic and, if applicable, IPv6 traffic. Outbound rules that allow unrestricted traffic to the internet can be a security risk. As a best practice, it is recommended to configure ACLs to restrict traffic on authorized protocols.\

#### Test Details
- eval: data.rule.acl_all_traffic_out
- id : PR-AWS-0118-CFR

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
| resourceTypes | ['aws::ec2::eip', 'aws::ec2::networkacl', 'aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::subnetnetworkaclassociation', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::ec2::networkaclentry', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/services/VPC/vpc_template.json']                                                                                                                                                                                                                                                                                                                           |

- masterTestId: TEST_NETWORKACL_6
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2networkacl.rego)
- severity: Medium

tags
| Title      | Description                         |
|:-----------|:------------------------------------|
| cloud      | git                                 |
| compliance | []                                  |
| service    | ['ec2networkacl', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0122-CFR
Title: AWS RDS database not encrypted using Customer Managed Key\
Test Result: **failed**\
Description : TThis policy identifies RDS databases that are encrypted with default KMS keys and not with customer managed keys. As a best practice, use customer managed keys to encrypt the data on your RDS databases and maintain control of your keys and data on sensitive workloads.\

#### Test Details
- eval: data.rule.rds_encrypt_key
- id : PR-AWS-0122-CFR

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
| resourceTypes | ['aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::rds::dbsubnetgroup', 'aws::ec2::subnetroutetableassociation', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::dms::replicationsubnetgroup', 'aws::dms::endpoint', 'aws::dms::replicationtask', 'aws::rds::dbcluster', 'aws::ec2::route', 'aws::rds::dbinstance', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_RDS_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/rds.rego)
- severity: Medium

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['rds', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0122-CFR
Title: AWS RDS database not encrypted using Customer Managed Key\
Test Result: **failed**\
Description : TThis policy identifies RDS databases that are encrypted with default KMS keys and not with customer managed keys. As a best practice, use customer managed keys to encrypt the data on your RDS databases and maintain control of your keys and data on sensitive workloads.\

#### Test Details
- eval: data.rule.rds_encrypt_key
- id : PR-AWS-0122-CFR

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
| resourceTypes | ['aws::rds::dbsecuritygroup', 'aws::rds::dbinstance', 'aws::ec2::securitygroup']                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_MySQL_With_Read_Replica.yaml'] |

- masterTestId: TEST_RDS_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/rds.rego)
- severity: Medium

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['rds', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0122-CFR
Title: AWS RDS database not encrypted using Customer Managed Key\
Test Result: **failed**\
Description : TThis policy identifies RDS databases that are encrypted with default KMS keys and not with customer managed keys. As a best practice, use customer managed keys to encrypt the data on your RDS databases and maintain control of your keys and data on sensitive workloads.\

#### Test Details
- eval: data.rule.rds_encrypt_key
- id : PR-AWS-0122-CFR

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

- masterTestId: TEST_RDS_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/rds.rego)
- severity: Medium

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['rds', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0122-CFR
Title: AWS RDS database not encrypted using Customer Managed Key\
Test Result: **failed**\
Description : TThis policy identifies RDS databases that are encrypted with default KMS keys and not with customer managed keys. As a best practice, use customer managed keys to encrypt the data on your RDS databases and maintain control of your keys and data on sensitive workloads.\

#### Test Details
- eval: data.rule.rds_encrypt_key
- id : PR-AWS-0122-CFR

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

- masterTestId: TEST_RDS_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/rds.rego)
- severity: Medium

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['rds', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0122-CFR
Title: AWS RDS database not encrypted using Customer Managed Key\
Test Result: **failed**\
Description : TThis policy identifies RDS databases that are encrypted with default KMS keys and not with customer managed keys. As a best practice, use customer managed keys to encrypt the data on your RDS databases and maintain control of your keys and data on sensitive workloads.\

#### Test Details
- eval: data.rule.rds_encrypt_key
- id : PR-AWS-0122-CFR

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
| resourceTypes | ['aws::rds::dbparametergroup', 'aws::rds::dbinstance']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/RDS/RDS_with_DBParameterGroup.yaml'] |

- masterTestId: TEST_RDS_9
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/rds.rego)
- severity: Medium

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['rds', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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
| resourceTypes | ['aws::config::configurationrecorder', 'aws::sns::topic', 'aws::sns::topicpolicy', 'aws::config::deliverychannel', 'aws::config::configrule', 'aws::s3::bucket', 'aws::iam::role', 'aws::lambda::function', 'aws::lambda::permission', 'aws::ec2::volume'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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
| resourceTypes | ['aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::rds::dbsubnetgroup', 'aws::ec2::subnetroutetableassociation', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::dms::replicationsubnetgroup', 'aws::dms::endpoint', 'aws::dms::replicationtask', 'aws::rds::dbcluster', 'aws::ec2::route', 'aws::rds::dbinstance', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::s3::bucket', 'aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **failed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **failed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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
| resourceTypes | ['aws::s3::bucket', 'custom::lambdatrig', 'aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::kms::alias', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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
| resourceTypes | ['aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroup', 'aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::s3::bucket', 'aws::ec2::instance', 'aws::cloudfront::distribution', 'aws::iam::role', 'aws::lambda::function', 'custom::lambdaversion', 'aws::kms::key', 'aws::ec2::securitygroupegress', 'aws::kms::alias', 'aws::elasticloadbalancingv2::listenerrule', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0147-CFR
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-0147-CFR

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
| resourceTypes | ['aws::ec2::flowlog', 'aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_S3_10
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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
| resourceTypes | ['aws::config::configurationrecorder', 'aws::sns::topic', 'aws::sns::topicpolicy', 'aws::config::deliverychannel', 'aws::config::configrule', 'aws::s3::bucket', 'aws::iam::role', 'aws::lambda::function', 'aws::lambda::permission', 'aws::ec2::volume'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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
| resourceTypes | ['aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::rds::dbsubnetgroup', 'aws::ec2::subnetroutetableassociation', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::dms::replicationsubnetgroup', 'aws::dms::endpoint', 'aws::dms::replicationtask', 'aws::rds::dbcluster', 'aws::ec2::route', 'aws::rds::dbinstance', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::s3::bucket', 'aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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
| resourceTypes | ['aws::s3::bucket', 'custom::lambdatrig', 'aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::kms::alias', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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
| resourceTypes | ['aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroup', 'aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::s3::bucket', 'aws::ec2::instance', 'aws::cloudfront::distribution', 'aws::iam::role', 'aws::lambda::function', 'custom::lambdaversion', 'aws::kms::key', 'aws::ec2::securitygroupegress', 'aws::kms::alias', 'aws::elasticloadbalancingv2::listenerrule', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0149-CFR
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-0149-CFR

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
| resourceTypes | ['aws::ec2::flowlog', 'aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_S3_11
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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
| resourceTypes | ['aws::config::configurationrecorder', 'aws::sns::topic', 'aws::sns::topicpolicy', 'aws::config::deliverychannel', 'aws::config::configrule', 'aws::s3::bucket', 'aws::iam::role', 'aws::lambda::function', 'aws::lambda::permission', 'aws::ec2::volume'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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
| resourceTypes | ['aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::rds::dbsubnetgroup', 'aws::ec2::subnetroutetableassociation', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::dms::replicationsubnetgroup', 'aws::dms::endpoint', 'aws::dms::replicationtask', 'aws::rds::dbcluster', 'aws::ec2::route', 'aws::rds::dbinstance', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::s3::bucket', 'aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **failed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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
| resourceTypes | ['aws::s3::bucket', 'custom::lambdatrig', 'aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::kms::alias', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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
| resourceTypes | ['aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroup', 'aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::s3::bucket', 'aws::ec2::instance', 'aws::cloudfront::distribution', 'aws::iam::role', 'aws::lambda::function', 'custom::lambdaversion', 'aws::kms::key', 'aws::ec2::securitygroupegress', 'aws::kms::alias', 'aws::elasticloadbalancingv2::listenerrule', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0150-CFR
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-0150-CFR

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
| resourceTypes | ['aws::ec2::flowlog', 'aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_S3_12
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: high

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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
| resourceTypes | ['aws::config::configurationrecorder', 'aws::sns::topic', 'aws::sns::topicpolicy', 'aws::config::deliverychannel', 'aws::config::configrule', 'aws::s3::bucket', 'aws::iam::role', 'aws::lambda::function', 'aws::lambda::permission', 'aws::ec2::volume'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Config/Config.yaml']                                                                                                                                                    |

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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
| resourceTypes | ['aws::rds::dbclusterparametergroup', 'aws::ec2::routetable', 'aws::dms::replicationinstance', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::rds::dbsubnetgroup', 'aws::ec2::subnetroutetableassociation', 'aws::s3::bucket', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::dms::replicationsubnetgroup', 'aws::dms::endpoint', 'aws::dms::replicationtask', 'aws::rds::dbcluster', 'aws::ec2::route', 'aws::rds::dbinstance', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DMS/DMSAuroraToS3FullLoadAndOngoingReplication.json']                                                                                                                                                                                                                                                                                                                                                        |

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::s3::bucket', 'aws::autoscaling::autoscalinggroup', 'aws::ec2::securitygroup', 'aws::autoscaling::launchconfiguration', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELB_Access_Logs_And_Connection_Draining.yaml']                                            |

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-delete-retention-v1.yaml'] |

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **passed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-sse-v1.yaml'] |

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-and-policy-for-caa-versioning-v1.yaml'] |

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **passed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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
| resourceTypes | ['aws::s3::bucket', 'custom::lambdatrig', 'aws::iam::role', 'aws::lambda::function', 'aws::kms::key', 'aws::kms::alias', 'aws::iam::managedpolicy', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AutomateCreatingHanaBackupBucket/CFT/CreateHanaBackupSecureBackut.yaml']                 |

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **passed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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
| resourceTypes | ['aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroup', 'aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::s3::bucket', 'aws::ec2::instance', 'aws::cloudfront::distribution', 'aws::iam::role', 'aws::lambda::function', 'custom::lambdaversion', 'aws::kms::key', 'aws::ec2::securitygroupegress', 'aws::kms::alias', 'aws::elasticloadbalancingv2::listenerrule', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **passed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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
| resourceTypes | ['aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/S3AccessLogs/templates/S3AccessLogs.cfn.yaml'] |

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0151-CFR
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **passed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-0151-CFR

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
| resourceTypes | ['aws::ec2::flowlog', 'aws::s3::bucket', 'aws::s3::bucketpolicy']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsS3.cfn.yaml'] |

- masterTestId: TEST_S3_13
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/s3.rego)
- severity: low

tags
| Title      | Description              |
|:-----------|:-------------------------|
| cloud      | git                      |
| compliance | []                       |
| service    | ['s3', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Stack.yaml']                                                                     |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2InstanceWithSecurityGroupSample.yaml'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EC2_Instance_With_Ephemeral_Drives.yaml'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::eipassociation', 'aws::ec2::eip', 'aws::ec2::securitygroup', 'aws::ec2::instance']                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/EIP_With_Association.yaml'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::elasticloadbalancing::loadbalancer', 'aws::ec2::securitygroup', 'aws::ec2::instance']                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/ELBStickinessSample.yaml'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/amazon_linux.template'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/centos.template'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/debian.template'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/redhat.template'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/suse.template'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/inline/ubuntu.template'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/amazon_linux.template'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/centos.template'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/debian.template'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/redhat.template'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/suse.template'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                               |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/AmazonCloudWatchAgent/ssm/ubuntu.template'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy-no-igw.yaml']                      |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::iam::instanceprofile', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::ec2::vpcendpoint', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-creationpolicy.yaml']                                                                                                                                                              |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition-no-igw.yaml']                                                                                                         |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::routetable', 'aws::ec2::subnet', 'aws::iam::instanceprofile', 'aws::ec2::vpcgatewayattachment', 'aws::ec2::subnetroutetableassociation', 'aws::ec2::instance', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::iam::role', 'aws::cloudformation::waitconditionhandle', 'aws::cloudformation::waitcondition', 'aws::ec2::vpcendpoint', 'aws::ec2::route', 'aws::ec2::securitygroup'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFormationEndpointSignals/cfn-endpoint-waitcondition.yaml']                                                                                                                                                                                                                                                 |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::elasticloadbalancingv2::targetgroup', 'aws::ec2::securitygroup', 'aws::ec2::securitygroupingress', 'aws::elasticloadbalancingv2::loadbalancer', 'aws::elasticloadbalancingv2::listener', 'aws::s3::bucket', 'aws::ec2::instance', 'aws::cloudfront::distribution', 'aws::iam::role', 'aws::lambda::function', 'custom::lambdaversion', 'aws::kms::key', 'aws::ec2::securitygroupegress', 'aws::kms::alias', 'aws::elasticloadbalancingv2::listenerrule', 'aws::s3::bucketpolicy'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/CloudFrontCustomOriginLambda@Edge/CloudFront.yaml']                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ssm::association', 'aws::ec2::instance']                                                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/DirectoryADClients/templates/DIRECTORY-AD-CLIENTS.yaml'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::iam::instanceprofile', 'aws::ec2::instance', 'aws::iam::role', 'aws::ssm::document', 'aws::ec2::securitygroup']   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/EC2DomainJoin/EC2-Domain-Join.json'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/HelperNonAmaznAmi/RHEL7_cfn-hup.template'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                                       |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/HelperNonAmaznAmi/ubuntu16.04LTS_cfn-hup.template'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0045-CFR
Title: AWS EC2 instance is not configured with VPC\
Test Result: **failed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-0045-CFR

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
| resourceTypes | ['aws::ec2::securitygroup', 'aws::ec2::instance']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/OperatingSystems/RHEL7_cfn-hup.cfn.yaml'] |

- masterTestId: TEST_EC2_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/ec2.rego)
- severity: high

tags
| Title      | Description               |
|:-----------|:--------------------------|
| cloud      | git                       |
| compliance | []                        |
| service    | ['ec2', 'cloudformation'] |
----------------------------------------------------------------

