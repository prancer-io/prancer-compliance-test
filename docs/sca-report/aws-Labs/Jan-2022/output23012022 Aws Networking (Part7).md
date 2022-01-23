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

## Aws Networking (Part7) Services

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

### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-CFR-SG-029

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

- masterTestId: PR-AWS-CFR-SG-029
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **failed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-CFR-SG-030

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

- masterTestId: PR-AWS-CFR-SG-030
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **failed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-CFR-SG-031

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

- masterTestId: PR-AWS-CFR-SG-031
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-CFR-SG-032

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

- masterTestId: PR-AWS-CFR-SG-032
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **failed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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


### Test ID - PR-AWS-CFR-SG-033
Title: Ensure Security groups has attached to a VPCs\
Test Result: **passed**\
Description : Ensure Security groups has attached to a VPCs else Shared security groups/port ranges lead to violation of principle of least privilege due to the reviewers not being aware that the security group/port range is shared.\

#### Test Details
- eval: data.rule.sg_vpc
- id : PR-AWS-CFR-SG-033

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

- masterTestId: PR-AWS-CFR-SG-033
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

