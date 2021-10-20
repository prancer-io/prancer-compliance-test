# Automated Vulnerability Scan result and Static Code Analysis for Aws Labs files (Oct 2021)

## https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/output10132021%20(Part1).md
## https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/output10132021%20(Part2).md
## https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/output10132021%20(Part3).md
## https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/output10132021%20(Part4).md
## https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/output10132021%20(Part5).md
## https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/output10132021%20(Part6).md
## https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/output10132021%20(Part7).md
## https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/output10132021%20(Part8).md
## https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/aws-Labs/output10132021%20(Part9).md

## Aws Labs Services (Part 8)

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

### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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
| resourceTypes | ['aws::iam::role', 'aws::cloudformation::macro', 'aws::lambda::function', 'aws::lambda::permission']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Macro.yaml'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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
| resourceTypes | ['aws::iam::role', 'aws::cloudformation::macro', 'aws::lambda::function', 'aws::lambda::permission']                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python.yaml'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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
| resourceTypes | ['aws::iam::role', 'aws::cloudformation::macro', 'aws::lambda::function', 'aws::lambda::permission']                                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string.yaml'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

#### Snapshots
| Title         | Description                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT20                                                                                                       |
| structure     | filesystem                                                                                                                    |
| reference     | master                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                           |
| collection    | cloudformationtemplate                                                                                                        |
| type          | cloudformation                                                                                                                |
| region        |                                                                                                                               |
| resourceTypes | ['aws::dynamodb::table']                                                                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DynamoDB/DynamoDB_Secondary_Indexes.yaml'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

#### Snapshots
| Title         | Description                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT21                                                                                           |
| structure     | filesystem                                                                                                        |
| reference     | master                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                               |
| collection    | cloudformationtemplate                                                                                            |
| type          | cloudformation                                                                                                    |
| region        |                                                                                                                   |
| resourceTypes | ['aws::dynamodb::table']                                                                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DynamoDB/DynamoDB_Table.yaml'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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
| resourceTypes | ['aws::ec2::eipassociation', 'aws::ec2::eip', 'aws::ec2::networkinterface']                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/SingleENIwithMultipleEIPs.json'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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
| resourceTypes | ['aws::ec2::eip', 'aws::elasticloadbalancingv2::targetgroup', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/NetworkLoadBalancerWithEIPs.json']          |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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
| resourceTypes | ['aws::emr::cluster', 'aws::iam::role', 'aws::iam::instanceprofile']                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EMR/EMRCLusterGangliaWithSparkOrS3backedHbase.json'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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
| resourceTypes | ['aws::emr::cluster', 'aws::iam::role', 'aws::iam::instanceprofile']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EMR/EMRClusterWithAdditioanalSecurityGroups.json'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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
| resourceTypes | ['aws::iam::user', 'aws::iam::accesskey', 'aws::iam::usertogroupaddition', 'aws::iam::group', 'aws::iam::policy']           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/IAM/IAM_Users_Groups_and_Policies.yaml'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

#### Snapshots
| Title         | Description                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT45                                                                                                                   |
| structure     | filesystem                                                                                                                                |
| reference     | master                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                    |
| type          | cloudformation                                                                                                                            |
| region        |                                                                                                                                           |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

#### Snapshots
| Title         | Description                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT46                                                                                                  |
| structure     | filesystem                                                                                                               |
| reference     | master                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                      |
| collection    | cloudformationtemplate                                                                                                   |
| type          | cloudformation                                                                                                           |
| region        |                                                                                                                          |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

#### Snapshots
| Title         | Description                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT49                                                                                            |
| structure     | filesystem                                                                                                         |
| reference     | master                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                |
| collection    | cloudformationtemplate                                                                                             |
| type          | cloudformation                                                                                                     |
| region        |                                                                                                                    |
| resourceTypes | ['aws::servicecatalog::tagoption', 'aws::servicecatalog::portfolioshare', 'aws::servicecatalog::portfolio']        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ServiceCatalog/Portfolio.yaml'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

#### Snapshots
| Title         | Description                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT50                                                                                                                         |
| structure     | filesystem                                                                                                                                      |
| reference     | master                                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                                             |
| collection    | cloudformationtemplate                                                                                                                          |
| type          | cloudformation                                                                                                                                  |
| region        |                                                                                                                                                 |
| resourceTypes | ['aws::servicecatalog::tagoptionassociation', 'aws::servicecatalog::cloudformationproduct', 'aws::servicecatalog::portfolioproductassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ServiceCatalog/Product.yaml']                                |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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
| resourceTypes | ['custom::vpceinterface', 'aws::iam::role', 'aws::lambda::function']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/createVPCInterfaceEndpoint/lambda_vpce_interface.json'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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
| resourceTypes | ['aws::ec2::vpcgatewayattachment', 'aws::iam::role', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::lambda::function', 'custom::routetablelambda', 'aws::ec2::route']          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/lambda-backed-cloudformation-custom-resources/get_vpc_main_route_table_id/RouteTable.template'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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
| resourceTypes | ['aws::logs::loggroup', 'aws::iam::role', 'aws::lambda::function']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/function-template.yaml'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

#### Snapshots
| Title         | Description                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT92                                                                                                                   |
| structure     | filesystem                                                                                                                                |
| reference     | master                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                    |
| type          | cloudformation                                                                                                                            |
| region        |                                                                                                                                           |
| resourceTypes | ['custom::stackset']                                                                                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/Templates/stack-set-template.yaml'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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
| resourceTypes | ['aws::logs::loggroup', 'aws::iam::role', 'aws::lambda::function']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/Templates/stackset-function-template.yaml'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::instance']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/TaggingRootVolumesInEC2/Tagging_Root_volume.yaml'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

#### Snapshots
| Title         | Description                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT96                                                                                                               |
| structure     | filesystem                                                                                                                            |
| reference     | master                                                                                                                                |
| source        | gitConnectorAwsLabs                                                                                                                   |
| collection    | cloudformationtemplate                                                                                                                |
| type          | cloudformation                                                                                                                        |
| region        |                                                                                                                                       |
| resourceTypes | ['aws::cloudformation::stack']                                                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogs-main.cfn.yaml'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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
| resourceTypes | ['aws::logs::loggroup', 'aws::iam::role', 'aws::ec2::flowlog']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsCloudWatch.cfn.yaml'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0028-RGX
Title: There is a possibility that AWS secret access key has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_secrets
- id : PR-AWS-0028-RGX

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
| resourceTypes | ['aws::iam::user', 'aws::iam::managedpolicy', 'aws::iam::policy']                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/solutions/read_only_user/read_only_user.json'] |

- masterTestId: TEST_SECRETS_1
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

#### Snapshots
| Title         | Description                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT4                                                                              |
| structure     | filesystem                                                                                          |
| reference     | master                                                                                              |
| source        | gitConnectorAwsLabs                                                                                 |
| collection    | cloudformationtemplate                                                                              |
| type          | cloudformation                                                                                      |
| region        |                                                                                                     |
| resourceTypes | ['aws::cloud9::environmentec2']                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Cloud9/C9.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

#### Snapshots
| Title         | Description                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT5                                                                                                                 |
| structure     | filesystem                                                                                                                             |
| reference     | master                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                 |
| type          | cloudformation                                                                                                                         |
| region        |                                                                                                                                        |
| resourceTypes | ['aws::cloudformation::macro', 'aws::serverless::function']                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/template.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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
| resourceTypes | ['aws::iam::role', 'aws::cloudformation::macro', 'aws::lambda::function', 'aws::lambda::permission']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Macro.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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
| resourceTypes | ['aws::iam::role', 'aws::cloudformation::macro', 'aws::lambda::function', 'aws::lambda::permission']                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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
| resourceTypes | ['aws::iam::role', 'aws::cloudformation::macro', 'aws::lambda::function', 'aws::lambda::permission']                                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

#### Snapshots
| Title         | Description                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT20                                                                                                       |
| structure     | filesystem                                                                                                                    |
| reference     | master                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                           |
| collection    | cloudformationtemplate                                                                                                        |
| type          | cloudformation                                                                                                                |
| region        |                                                                                                                               |
| resourceTypes | ['aws::dynamodb::table']                                                                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DynamoDB/DynamoDB_Secondary_Indexes.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

#### Snapshots
| Title         | Description                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT21                                                                                           |
| structure     | filesystem                                                                                                        |
| reference     | master                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                               |
| collection    | cloudformationtemplate                                                                                            |
| type          | cloudformation                                                                                                    |
| region        |                                                                                                                   |
| resourceTypes | ['aws::dynamodb::table']                                                                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DynamoDB/DynamoDB_Table.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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
| resourceTypes | ['aws::ec2::eipassociation', 'aws::ec2::eip', 'aws::ec2::networkinterface']                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/SingleENIwithMultipleEIPs.json'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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
| resourceTypes | ['aws::ec2::eip', 'aws::elasticloadbalancingv2::targetgroup', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/NetworkLoadBalancerWithEIPs.json']          |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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
| resourceTypes | ['aws::emr::cluster', 'aws::iam::role', 'aws::iam::instanceprofile']                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EMR/EMRCLusterGangliaWithSparkOrS3backedHbase.json'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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
| resourceTypes | ['aws::emr::cluster', 'aws::iam::role', 'aws::iam::instanceprofile']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EMR/EMRClusterWithAdditioanalSecurityGroups.json'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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
| resourceTypes | ['aws::iam::user', 'aws::iam::accesskey', 'aws::iam::usertogroupaddition', 'aws::iam::group', 'aws::iam::policy']           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/IAM/IAM_Users_Groups_and_Policies.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

#### Snapshots
| Title         | Description                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT45                                                                                                                   |
| structure     | filesystem                                                                                                                                |
| reference     | master                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                    |
| type          | cloudformation                                                                                                                            |
| region        |                                                                                                                                           |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

#### Snapshots
| Title         | Description                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT46                                                                                                  |
| structure     | filesystem                                                                                                               |
| reference     | master                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                      |
| collection    | cloudformationtemplate                                                                                                   |
| type          | cloudformation                                                                                                           |
| region        |                                                                                                                          |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

#### Snapshots
| Title         | Description                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT49                                                                                            |
| structure     | filesystem                                                                                                         |
| reference     | master                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                |
| collection    | cloudformationtemplate                                                                                             |
| type          | cloudformation                                                                                                     |
| region        |                                                                                                                    |
| resourceTypes | ['aws::servicecatalog::tagoption', 'aws::servicecatalog::portfolioshare', 'aws::servicecatalog::portfolio']        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ServiceCatalog/Portfolio.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

#### Snapshots
| Title         | Description                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT50                                                                                                                         |
| structure     | filesystem                                                                                                                                      |
| reference     | master                                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                                             |
| collection    | cloudformationtemplate                                                                                                                          |
| type          | cloudformation                                                                                                                                  |
| region        |                                                                                                                                                 |
| resourceTypes | ['aws::servicecatalog::tagoptionassociation', 'aws::servicecatalog::cloudformationproduct', 'aws::servicecatalog::portfolioproductassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ServiceCatalog/Product.yaml']                                |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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
| resourceTypes | ['custom::vpceinterface', 'aws::iam::role', 'aws::lambda::function']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/createVPCInterfaceEndpoint/lambda_vpce_interface.json'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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
| resourceTypes | ['aws::ec2::vpcgatewayattachment', 'aws::iam::role', 'aws::ec2::vpc', 'aws::ec2::internetgateway', 'aws::lambda::function', 'custom::routetablelambda', 'aws::ec2::route']          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/lambda-backed-cloudformation-custom-resources/get_vpc_main_route_table_id/RouteTable.template'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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
| resourceTypes | ['aws::logs::loggroup', 'aws::iam::role', 'aws::lambda::function']                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/PrefixListResource/Templates/function-template.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

#### Snapshots
| Title         | Description                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT92                                                                                                                   |
| structure     | filesystem                                                                                                                                |
| reference     | master                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                    |
| type          | cloudformation                                                                                                                            |
| region        |                                                                                                                                           |
| resourceTypes | ['custom::stackset']                                                                                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/Templates/stack-set-template.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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
| resourceTypes | ['aws::logs::loggroup', 'aws::iam::role', 'aws::lambda::function']                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/StackSetsResource/Templates/stackset-function-template.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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
| resourceTypes | ['aws::iam::role', 'aws::iam::instanceprofile', 'aws::ec2::instance']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/TaggingRootVolumesInEC2/Tagging_Root_volume.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

#### Snapshots
| Title         | Description                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT96                                                                                                               |
| structure     | filesystem                                                                                                                            |
| reference     | master                                                                                                                                |
| source        | gitConnectorAwsLabs                                                                                                                   |
| collection    | cloudformationtemplate                                                                                                                |
| type          | cloudformation                                                                                                                        |
| region        |                                                                                                                                       |
| resourceTypes | ['aws::cloudformation::stack']                                                                                                        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogs-main.cfn.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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
| resourceTypes | ['aws::logs::loggroup', 'aws::iam::role', 'aws::ec2::flowlog']                                                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/solutions/VPCFlowLogs/templates/VPCFlowLogsCloudWatch.cfn.yaml'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0029-RGX
Title: There is a possibility that AWS account ID has leaked\
Test Result: **passed**\
Description : There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: gl_aws_account
- id : PR-AWS-0029-RGX

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
| resourceTypes | ['aws::iam::user', 'aws::iam::managedpolicy', 'aws::iam::policy']                                                              |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/community/solutions/read_only_user/read_only_user.json'] |

- masterTestId: TEST_SECRETS_2
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

#### Snapshots
| Title         | Description                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT4                                                                              |
| structure     | filesystem                                                                                          |
| reference     | master                                                                                              |
| source        | gitConnectorAwsLabs                                                                                 |
| collection    | cloudformationtemplate                                                                              |
| type          | cloudformation                                                                                      |
| region        |                                                                                                     |
| resourceTypes | ['aws::cloud9::environmentec2']                                                                     |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/Cloud9/C9.yaml'] |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

#### Snapshots
| Title         | Description                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT5                                                                                                                 |
| structure     | filesystem                                                                                                                             |
| reference     | master                                                                                                                                 |
| source        | gitConnectorAwsLabs                                                                                                                    |
| collection    | cloudformationtemplate                                                                                                                 |
| type          | cloudformation                                                                                                                         |
| region        |                                                                                                                                        |
| resourceTypes | ['aws::cloudformation::macro', 'aws::serverless::function']                                                                            |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Count/template.yaml'] |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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
| resourceTypes | ['aws::iam::role', 'aws::cloudformation::macro', 'aws::lambda::function', 'aws::lambda::permission']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/Public-and-Private-Subnet-per-AZ/Create-Macro.yaml'] |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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
| resourceTypes | ['aws::iam::role', 'aws::cloudformation::macro', 'aws::lambda::function', 'aws::lambda::permission']                                   |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/PyPlate/python.yaml'] |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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
| resourceTypes | ['aws::iam::role', 'aws::cloudformation::macro', 'aws::lambda::function', 'aws::lambda::permission']                                           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/CloudFormation/MacrosExamples/StringFunctions/string.yaml'] |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

#### Snapshots
| Title         | Description                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT20                                                                                                       |
| structure     | filesystem                                                                                                                    |
| reference     | master                                                                                                                        |
| source        | gitConnectorAwsLabs                                                                                                           |
| collection    | cloudformationtemplate                                                                                                        |
| type          | cloudformation                                                                                                                |
| region        |                                                                                                                               |
| resourceTypes | ['aws::dynamodb::table']                                                                                                      |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DynamoDB/DynamoDB_Secondary_Indexes.yaml'] |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

#### Snapshots
| Title         | Description                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT21                                                                                           |
| structure     | filesystem                                                                                                        |
| reference     | master                                                                                                            |
| source        | gitConnectorAwsLabs                                                                                               |
| collection    | cloudformationtemplate                                                                                            |
| type          | cloudformation                                                                                                    |
| region        |                                                                                                                   |
| resourceTypes | ['aws::dynamodb::table']                                                                                          |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/DynamoDB/DynamoDB_Table.yaml'] |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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
| resourceTypes | ['aws::ec2::eipassociation', 'aws::ec2::eip', 'aws::ec2::networkinterface']                                             |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EC2/SingleENIwithMultipleEIPs.json'] |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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
| resourceTypes | ['aws::ec2::eip', 'aws::elasticloadbalancingv2::targetgroup', 'aws::elasticloadbalancingv2::listener', 'aws::elasticloadbalancingv2::loadbalancer'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ElasticLoadBalancing/NetworkLoadBalancerWithEIPs.json']          |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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
| resourceTypes | ['aws::emr::cluster', 'aws::iam::role', 'aws::iam::instanceprofile']                                                                    |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EMR/EMRCLusterGangliaWithSparkOrS3backedHbase.json'] |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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
| resourceTypes | ['aws::emr::cluster', 'aws::iam::role', 'aws::iam::instanceprofile']                                                                  |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/EMR/EMRClusterWithAdditioanalSecurityGroups.json'] |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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
| resourceTypes | ['aws::iam::user', 'aws::iam::accesskey', 'aws::iam::usertogroupaddition', 'aws::iam::group', 'aws::iam::policy']           |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/IAM/IAM_Users_Groups_and_Policies.yaml'] |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

#### Snapshots
| Title         | Description                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT45                                                                                                                   |
| structure     | filesystem                                                                                                                                |
| reference     | master                                                                                                                                    |
| source        | gitConnectorAwsLabs                                                                                                                       |
| collection    | cloudformationtemplate                                                                                                                    |
| type          | cloudformation                                                                                                                            |
| region        |                                                                                                                                           |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                                 |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-secure-transport-v1.yaml'] |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

#### Snapshots
| Title         | Description                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT46                                                                                                  |
| structure     | filesystem                                                                                                               |
| reference     | master                                                                                                                   |
| source        | gitConnectorAwsLabs                                                                                                      |
| collection    | cloudformationtemplate                                                                                                   |
| type          | cloudformation                                                                                                           |
| region        |                                                                                                                          |
| resourceTypes | ['aws::s3::bucketpolicy']                                                                                                |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/S3/s3-bucket-policy-for-caa-v1.yaml'] |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

#### Snapshots
| Title         | Description                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT49                                                                                            |
| structure     | filesystem                                                                                                         |
| reference     | master                                                                                                             |
| source        | gitConnectorAwsLabs                                                                                                |
| collection    | cloudformationtemplate                                                                                             |
| type          | cloudformation                                                                                                     |
| region        |                                                                                                                    |
| resourceTypes | ['aws::servicecatalog::tagoption', 'aws::servicecatalog::portfolioshare', 'aws::servicecatalog::portfolio']        |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ServiceCatalog/Portfolio.yaml'] |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

#### Snapshots
| Title         | Description                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | CFR_TEMPLATE_SNAPSHOT50                                                                                                                         |
| structure     | filesystem                                                                                                                                      |
| reference     | master                                                                                                                                          |
| source        | gitConnectorAwsLabs                                                                                                                             |
| collection    | cloudformationtemplate                                                                                                                          |
| type          | cloudformation                                                                                                                                  |
| region        |                                                                                                                                                 |
| resourceTypes | ['aws::servicecatalog::tagoptionassociation', 'aws::servicecatalog::cloudformationproduct', 'aws::servicecatalog::portfolioproductassociation'] |
| paths         | ['https://github.com/awslabs/aws-cloudformation-templates/tree/master/aws/services/ServiceCatalog/Product.yaml']                                |

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------


### Test ID - PR-AWS-0030-RGX
Title: There is a possibility that Aws access key id is exposed\
Test Result: **passed**\
Description : There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault\

#### Test Details
- eval: al_access_key_id
- id : PR-AWS-0030-RGX

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

- masterTestId: TEST_SECRETS_3
- masterSnapshotId: ['CFR_TEMPLATE_SNAPSHOT']
- type: python
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/secret_aws_iac.py)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | []                 |
| service    | ['cloudformation'] |
----------------------------------------------------------------

