# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AWS (Dec 2021)

#### Compute: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Dec-2021/output11182021%20Aws%20Compute.md
#### Data Store: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Dec-2021/output11182021%20Aws%20DataStore.md
#### Management: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Dec-2021/output11182021%20Aws%20Management.md
#### Networking (Part1): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Dec-2021/output11182021%20Aws%20Networking%20(Part1).md
#### Networking (Part2): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Dec-2021/output11182021%20Aws%20Networking%20(Part2).md
#### Networking (Part3): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Dec-2021/output11182021%20Aws%20Networking%20(Part3).md
#### Security: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Dec-2021/output11232021%20Aws%20Security.md

## Terraform Aws Networking (Part2) Services

Source Repository: https://github.com/hashicorp/terraform-provider-aws

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/

## Compliance run Meta Data
| Title     | Description                      |
|:----------|:---------------------------------|
| timestamp | 1640206336368                    |
| snapshot  | master-snapshot_gen              |
| container | scenario-aws-terraform-hashicorp |
| test      | master-test.json                 |

## Results

### Test ID - PR-AWS-TRF-SG-007
Title: AWS Security Groups allow internet traffic from internet to FTP port (21)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing FTP port (21) to the internet. It is recommended that Global permission to access the well known services FTP port (21) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_21
- id : PR-AWS-TRF-SG-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT30                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg.tf'] |

- masterTestId: TEST_SECURITY_GROUP_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-007
Title: AWS Security Groups allow internet traffic from internet to FTP port (21)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing FTP port (21) to the internet. It is recommended that Global permission to access the well known services FTP port (21) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_21
- id : PR-AWS-TRF-SG-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws_instance', 'aws_route', 'aws_internet_gateway', 'aws_elb', 'aws_vpc', 'aws_key_pair', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-008
Title: AWS Security Groups allow internet traffic to SSH port (22)\
Test Result: **failed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on SSH port (22) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_22
- id : PR-AWS-TRF-SG-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group', 'aws_security_group']                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-008
Title: AWS Security Groups allow internet traffic to SSH port (22)\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on SSH port (22) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_22
- id : PR-AWS-TRF-SG-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT12                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_iam_role', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_internet_gateway', 'aws_iam_instance_profile', 'aws_vpc', 'aws_alb_listener', 'aws_autoscaling_group', 'aws_alb_target_group', 'aws_alb', 'aws_route_table', 'aws_ecs_task_definition', 'aws_launch_configuration', 'aws_iam_role_policy', 'aws_subnet', 'aws_ecs_service', 'aws_ecs_cluster', 'aws_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_SECURITY_GROUP_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-008
Title: AWS Security Groups allow internet traffic to SSH port (22)\
Test Result: **failed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on SSH port (22) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_22
- id : PR-AWS-TRF-SG-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT13                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_eip', 'aws_instance', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-008
Title: AWS Security Groups allow internet traffic to SSH port (22)\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on SSH port (22) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_22
- id : PR-AWS-TRF-SG-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT14                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_eks_cluster', 'aws_iam_role', 'aws_security_group_rule', 'aws_iam_role_policy_attachment', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-008
Title: AWS Security Groups allow internet traffic to SSH port (22)\
Test Result: **failed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on SSH port (22) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_22
- id : PR-AWS-TRF-SG-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_instance', 'aws_route_table_association', 'aws_internet_gateway', 'aws_elb', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-008
Title: AWS Security Groups allow internet traffic to SSH port (22)\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on SSH port (22) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_22
- id : PR-AWS-TRF-SG-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT23                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-008
Title: AWS Security Groups allow internet traffic to SSH port (22)\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on SSH port (22) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_22
- id : PR-AWS-TRF-SG-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT24                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_route_table_association', 'aws_subnet', 'aws_route_table', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/subnets.tf'] |

- masterTestId: TEST_SECURITY_GROUP_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-008
Title: AWS Security Groups allow internet traffic to SSH port (22)\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on SSH port (22) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_22
- id : PR-AWS-TRF-SG-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-008
Title: AWS Security Groups allow internet traffic to SSH port (22)\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on SSH port (22) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_22
- id : PR-AWS-TRF-SG-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT28                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_route_table_association', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/regions.tf'] |

- masterTestId: TEST_SECURITY_GROUP_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-008
Title: AWS Security Groups allow internet traffic to SSH port (22)\
Test Result: **failed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on SSH port (22) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_22
- id : PR-AWS-TRF-SG-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT30                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg.tf'] |

- masterTestId: TEST_SECURITY_GROUP_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-008
Title: AWS Security Groups allow internet traffic to SSH port (22)\
Test Result: **failed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on SSH port (22) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_22
- id : PR-AWS-TRF-SG-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws_instance', 'aws_route', 'aws_internet_gateway', 'aws_elb', 'aws_vpc', 'aws_key_pair', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-009
Title: AWS Security Groups allow internet traffic from internet to Telnet port (23)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Telnet port (23) to the internet. It is recommended that Global permission to access the well known services Telnet port (23) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_23
- id : PR-AWS-TRF-SG-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group', 'aws_security_group']                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-009
Title: AWS Security Groups allow internet traffic from internet to Telnet port (23)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Telnet port (23) to the internet. It is recommended that Global permission to access the well known services Telnet port (23) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_23
- id : PR-AWS-TRF-SG-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT12                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_iam_role', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_internet_gateway', 'aws_iam_instance_profile', 'aws_vpc', 'aws_alb_listener', 'aws_autoscaling_group', 'aws_alb_target_group', 'aws_alb', 'aws_route_table', 'aws_ecs_task_definition', 'aws_launch_configuration', 'aws_iam_role_policy', 'aws_subnet', 'aws_ecs_service', 'aws_ecs_cluster', 'aws_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_SECURITY_GROUP_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-009
Title: AWS Security Groups allow internet traffic from internet to Telnet port (23)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Telnet port (23) to the internet. It is recommended that Global permission to access the well known services Telnet port (23) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_23
- id : PR-AWS-TRF-SG-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT13                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_eip', 'aws_instance', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-009
Title: AWS Security Groups allow internet traffic from internet to Telnet port (23)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Telnet port (23) to the internet. It is recommended that Global permission to access the well known services Telnet port (23) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_23
- id : PR-AWS-TRF-SG-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT14                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_eks_cluster', 'aws_iam_role', 'aws_security_group_rule', 'aws_iam_role_policy_attachment', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-009
Title: AWS Security Groups allow internet traffic from internet to Telnet port (23)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Telnet port (23) to the internet. It is recommended that Global permission to access the well known services Telnet port (23) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_23
- id : PR-AWS-TRF-SG-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_instance', 'aws_route_table_association', 'aws_internet_gateway', 'aws_elb', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-009
Title: AWS Security Groups allow internet traffic from internet to Telnet port (23)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Telnet port (23) to the internet. It is recommended that Global permission to access the well known services Telnet port (23) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_23
- id : PR-AWS-TRF-SG-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT23                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-009
Title: AWS Security Groups allow internet traffic from internet to Telnet port (23)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Telnet port (23) to the internet. It is recommended that Global permission to access the well known services Telnet port (23) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_23
- id : PR-AWS-TRF-SG-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT24                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_route_table_association', 'aws_subnet', 'aws_route_table', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/subnets.tf'] |

- masterTestId: TEST_SECURITY_GROUP_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-009
Title: AWS Security Groups allow internet traffic from internet to Telnet port (23)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Telnet port (23) to the internet. It is recommended that Global permission to access the well known services Telnet port (23) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_23
- id : PR-AWS-TRF-SG-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-009
Title: AWS Security Groups allow internet traffic from internet to Telnet port (23)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Telnet port (23) to the internet. It is recommended that Global permission to access the well known services Telnet port (23) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_23
- id : PR-AWS-TRF-SG-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT28                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_route_table_association', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/regions.tf'] |

- masterTestId: TEST_SECURITY_GROUP_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-009
Title: AWS Security Groups allow internet traffic from internet to Telnet port (23)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing Telnet port (23) to the internet. It is recommended that Global permission to access the well known services Telnet port (23) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_23
- id : PR-AWS-TRF-SG-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT30                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg.tf'] |

- masterTestId: TEST_SECURITY_GROUP_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-009
Title: AWS Security Groups allow internet traffic from internet to Telnet port (23)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Telnet port (23) to the internet. It is recommended that Global permission to access the well known services Telnet port (23) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_23
- id : PR-AWS-TRF-SG-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws_instance', 'aws_route', 'aws_internet_gateway', 'aws_elb', 'aws_vpc', 'aws_key_pair', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-010
Title: AWS Security Groups allow internet traffic from internet to SMTP port (25)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SMTP port (25) to the internet. It is recommended that Global permission to access the well known services SMTP port (25) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_25
- id : PR-AWS-TRF-SG-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group', 'aws_security_group']                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_10
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-010
Title: AWS Security Groups allow internet traffic from internet to SMTP port (25)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SMTP port (25) to the internet. It is recommended that Global permission to access the well known services SMTP port (25) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_25
- id : PR-AWS-TRF-SG-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT12                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_iam_role', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_internet_gateway', 'aws_iam_instance_profile', 'aws_vpc', 'aws_alb_listener', 'aws_autoscaling_group', 'aws_alb_target_group', 'aws_alb', 'aws_route_table', 'aws_ecs_task_definition', 'aws_launch_configuration', 'aws_iam_role_policy', 'aws_subnet', 'aws_ecs_service', 'aws_ecs_cluster', 'aws_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_SECURITY_GROUP_10
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-010
Title: AWS Security Groups allow internet traffic from internet to SMTP port (25)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SMTP port (25) to the internet. It is recommended that Global permission to access the well known services SMTP port (25) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_25
- id : PR-AWS-TRF-SG-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT13                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_eip', 'aws_instance', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_10
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-010
Title: AWS Security Groups allow internet traffic from internet to SMTP port (25)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SMTP port (25) to the internet. It is recommended that Global permission to access the well known services SMTP port (25) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_25
- id : PR-AWS-TRF-SG-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT14                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_eks_cluster', 'aws_iam_role', 'aws_security_group_rule', 'aws_iam_role_policy_attachment', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_10
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-010
Title: AWS Security Groups allow internet traffic from internet to SMTP port (25)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SMTP port (25) to the internet. It is recommended that Global permission to access the well known services SMTP port (25) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_25
- id : PR-AWS-TRF-SG-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_instance', 'aws_route_table_association', 'aws_internet_gateway', 'aws_elb', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_10
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-010
Title: AWS Security Groups allow internet traffic from internet to SMTP port (25)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SMTP port (25) to the internet. It is recommended that Global permission to access the well known services SMTP port (25) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_25
- id : PR-AWS-TRF-SG-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT23                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_10
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-010
Title: AWS Security Groups allow internet traffic from internet to SMTP port (25)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SMTP port (25) to the internet. It is recommended that Global permission to access the well known services SMTP port (25) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_25
- id : PR-AWS-TRF-SG-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT24                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_route_table_association', 'aws_subnet', 'aws_route_table', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/subnets.tf'] |

- masterTestId: TEST_SECURITY_GROUP_10
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-010
Title: AWS Security Groups allow internet traffic from internet to SMTP port (25)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SMTP port (25) to the internet. It is recommended that Global permission to access the well known services SMTP port (25) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_25
- id : PR-AWS-TRF-SG-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_10
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-010
Title: AWS Security Groups allow internet traffic from internet to SMTP port (25)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SMTP port (25) to the internet. It is recommended that Global permission to access the well known services SMTP port (25) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_25
- id : PR-AWS-TRF-SG-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT28                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_route_table_association', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/regions.tf'] |

- masterTestId: TEST_SECURITY_GROUP_10
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-010
Title: AWS Security Groups allow internet traffic from internet to SMTP port (25)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing SMTP port (25) to the internet. It is recommended that Global permission to access the well known services SMTP port (25) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_25
- id : PR-AWS-TRF-SG-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT30                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg.tf'] |

- masterTestId: TEST_SECURITY_GROUP_10
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-010
Title: AWS Security Groups allow internet traffic from internet to SMTP port (25)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SMTP port (25) to the internet. It is recommended that Global permission to access the well known services SMTP port (25) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_25
- id : PR-AWS-TRF-SG-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws_instance', 'aws_route', 'aws_internet_gateway', 'aws_elb', 'aws_vpc', 'aws_key_pair', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_10
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-011
Title: AWS Security Groups allow internet traffic from internet to MYSQL port (3306)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MYSQL port (3306) to the internet. It is recommended that Global permission to access the well known services MYSQL port (3306) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_3306
- id : PR-AWS-TRF-SG-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group', 'aws_security_group']                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_11
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-011
Title: AWS Security Groups allow internet traffic from internet to MYSQL port (3306)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MYSQL port (3306) to the internet. It is recommended that Global permission to access the well known services MYSQL port (3306) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_3306
- id : PR-AWS-TRF-SG-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT12                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_iam_role', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_internet_gateway', 'aws_iam_instance_profile', 'aws_vpc', 'aws_alb_listener', 'aws_autoscaling_group', 'aws_alb_target_group', 'aws_alb', 'aws_route_table', 'aws_ecs_task_definition', 'aws_launch_configuration', 'aws_iam_role_policy', 'aws_subnet', 'aws_ecs_service', 'aws_ecs_cluster', 'aws_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_SECURITY_GROUP_11
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-011
Title: AWS Security Groups allow internet traffic from internet to MYSQL port (3306)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MYSQL port (3306) to the internet. It is recommended that Global permission to access the well known services MYSQL port (3306) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_3306
- id : PR-AWS-TRF-SG-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT13                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_eip', 'aws_instance', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_11
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-011
Title: AWS Security Groups allow internet traffic from internet to MYSQL port (3306)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MYSQL port (3306) to the internet. It is recommended that Global permission to access the well known services MYSQL port (3306) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_3306
- id : PR-AWS-TRF-SG-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT14                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_eks_cluster', 'aws_iam_role', 'aws_security_group_rule', 'aws_iam_role_policy_attachment', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_11
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-011
Title: AWS Security Groups allow internet traffic from internet to MYSQL port (3306)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MYSQL port (3306) to the internet. It is recommended that Global permission to access the well known services MYSQL port (3306) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_3306
- id : PR-AWS-TRF-SG-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_instance', 'aws_route_table_association', 'aws_internet_gateway', 'aws_elb', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_11
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-011
Title: AWS Security Groups allow internet traffic from internet to MYSQL port (3306)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MYSQL port (3306) to the internet. It is recommended that Global permission to access the well known services MYSQL port (3306) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_3306
- id : PR-AWS-TRF-SG-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT23                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_11
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-011
Title: AWS Security Groups allow internet traffic from internet to MYSQL port (3306)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MYSQL port (3306) to the internet. It is recommended that Global permission to access the well known services MYSQL port (3306) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_3306
- id : PR-AWS-TRF-SG-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT24                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_route_table_association', 'aws_subnet', 'aws_route_table', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/subnets.tf'] |

- masterTestId: TEST_SECURITY_GROUP_11
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-011
Title: AWS Security Groups allow internet traffic from internet to MYSQL port (3306)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MYSQL port (3306) to the internet. It is recommended that Global permission to access the well known services MYSQL port (3306) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_3306
- id : PR-AWS-TRF-SG-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_11
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-011
Title: AWS Security Groups allow internet traffic from internet to MYSQL port (3306)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MYSQL port (3306) to the internet. It is recommended that Global permission to access the well known services MYSQL port (3306) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_3306
- id : PR-AWS-TRF-SG-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT28                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_route_table_association', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/regions.tf'] |

- masterTestId: TEST_SECURITY_GROUP_11
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-011
Title: AWS Security Groups allow internet traffic from internet to MYSQL port (3306)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing MYSQL port (3306) to the internet. It is recommended that Global permission to access the well known services MYSQL port (3306) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_3306
- id : PR-AWS-TRF-SG-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT30                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg.tf'] |

- masterTestId: TEST_SECURITY_GROUP_11
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-011
Title: AWS Security Groups allow internet traffic from internet to MYSQL port (3306)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MYSQL port (3306) to the internet. It is recommended that Global permission to access the well known services MYSQL port (3306) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_3306
- id : PR-AWS-TRF-SG-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws_instance', 'aws_route', 'aws_internet_gateway', 'aws_elb', 'aws_vpc', 'aws_key_pair', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_11
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-012
Title: AWS Security Groups allow internet traffic from internet to RDP port (3389)\
Test Result: **passed**\
Description : This policy identifies the security groups which is exposing RDP port (3389) to the internet. Security Groups do not allow inbound traffic on RDP port (3389) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_3389
- id : PR-AWS-TRF-SG-012

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group', 'aws_security_group']                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_12
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-012
Title: AWS Security Groups allow internet traffic from internet to RDP port (3389)\
Test Result: **passed**\
Description : This policy identifies the security groups which is exposing RDP port (3389) to the internet. Security Groups do not allow inbound traffic on RDP port (3389) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_3389
- id : PR-AWS-TRF-SG-012

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT12                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_iam_role', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_internet_gateway', 'aws_iam_instance_profile', 'aws_vpc', 'aws_alb_listener', 'aws_autoscaling_group', 'aws_alb_target_group', 'aws_alb', 'aws_route_table', 'aws_ecs_task_definition', 'aws_launch_configuration', 'aws_iam_role_policy', 'aws_subnet', 'aws_ecs_service', 'aws_ecs_cluster', 'aws_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_SECURITY_GROUP_12
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-012
Title: AWS Security Groups allow internet traffic from internet to RDP port (3389)\
Test Result: **passed**\
Description : This policy identifies the security groups which is exposing RDP port (3389) to the internet. Security Groups do not allow inbound traffic on RDP port (3389) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_3389
- id : PR-AWS-TRF-SG-012

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT13                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_eip', 'aws_instance', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_12
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-012
Title: AWS Security Groups allow internet traffic from internet to RDP port (3389)\
Test Result: **passed**\
Description : This policy identifies the security groups which is exposing RDP port (3389) to the internet. Security Groups do not allow inbound traffic on RDP port (3389) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_3389
- id : PR-AWS-TRF-SG-012

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT14                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_eks_cluster', 'aws_iam_role', 'aws_security_group_rule', 'aws_iam_role_policy_attachment', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_12
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-012
Title: AWS Security Groups allow internet traffic from internet to RDP port (3389)\
Test Result: **passed**\
Description : This policy identifies the security groups which is exposing RDP port (3389) to the internet. Security Groups do not allow inbound traffic on RDP port (3389) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_3389
- id : PR-AWS-TRF-SG-012

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_instance', 'aws_route_table_association', 'aws_internet_gateway', 'aws_elb', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_12
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-012
Title: AWS Security Groups allow internet traffic from internet to RDP port (3389)\
Test Result: **passed**\
Description : This policy identifies the security groups which is exposing RDP port (3389) to the internet. Security Groups do not allow inbound traffic on RDP port (3389) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_3389
- id : PR-AWS-TRF-SG-012

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT23                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_12
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-012
Title: AWS Security Groups allow internet traffic from internet to RDP port (3389)\
Test Result: **passed**\
Description : This policy identifies the security groups which is exposing RDP port (3389) to the internet. Security Groups do not allow inbound traffic on RDP port (3389) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_3389
- id : PR-AWS-TRF-SG-012

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT24                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_route_table_association', 'aws_subnet', 'aws_route_table', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/subnets.tf'] |

- masterTestId: TEST_SECURITY_GROUP_12
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-012
Title: AWS Security Groups allow internet traffic from internet to RDP port (3389)\
Test Result: **passed**\
Description : This policy identifies the security groups which is exposing RDP port (3389) to the internet. Security Groups do not allow inbound traffic on RDP port (3389) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_3389
- id : PR-AWS-TRF-SG-012

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_12
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-012
Title: AWS Security Groups allow internet traffic from internet to RDP port (3389)\
Test Result: **passed**\
Description : This policy identifies the security groups which is exposing RDP port (3389) to the internet. Security Groups do not allow inbound traffic on RDP port (3389) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_3389
- id : PR-AWS-TRF-SG-012

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT28                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_route_table_association', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/regions.tf'] |

- masterTestId: TEST_SECURITY_GROUP_12
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-012
Title: AWS Security Groups allow internet traffic from internet to RDP port (3389)\
Test Result: **failed**\
Description : This policy identifies the security groups which is exposing RDP port (3389) to the internet. Security Groups do not allow inbound traffic on RDP port (3389) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_3389
- id : PR-AWS-TRF-SG-012

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT30                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg.tf'] |

- masterTestId: TEST_SECURITY_GROUP_12
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-012
Title: AWS Security Groups allow internet traffic from internet to RDP port (3389)\
Test Result: **passed**\
Description : This policy identifies the security groups which is exposing RDP port (3389) to the internet. Security Groups do not allow inbound traffic on RDP port (3389) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_3389
- id : PR-AWS-TRF-SG-012

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws_instance', 'aws_route', 'aws_internet_gateway', 'aws_elb', 'aws_vpc', 'aws_key_pair', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_12
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                                                  |
|:-----------|:---------------------------------------------------------------------------------------------|
| cloud      | git                                                                                          |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                                                |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-013
Title: AWS Security Groups allow internet traffic from internet to MSQL port (4333)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MSQL port (4333) to the internet. It is recommended that Global permission to access the well known services MSQL port (4333) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_4333
- id : PR-AWS-TRF-SG-013

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group', 'aws_security_group']                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_13
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-013
Title: AWS Security Groups allow internet traffic from internet to MSQL port (4333)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MSQL port (4333) to the internet. It is recommended that Global permission to access the well known services MSQL port (4333) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_4333
- id : PR-AWS-TRF-SG-013

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT12                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_iam_role', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_internet_gateway', 'aws_iam_instance_profile', 'aws_vpc', 'aws_alb_listener', 'aws_autoscaling_group', 'aws_alb_target_group', 'aws_alb', 'aws_route_table', 'aws_ecs_task_definition', 'aws_launch_configuration', 'aws_iam_role_policy', 'aws_subnet', 'aws_ecs_service', 'aws_ecs_cluster', 'aws_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_SECURITY_GROUP_13
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-013
Title: AWS Security Groups allow internet traffic from internet to MSQL port (4333)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MSQL port (4333) to the internet. It is recommended that Global permission to access the well known services MSQL port (4333) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_4333
- id : PR-AWS-TRF-SG-013

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT13                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_eip', 'aws_instance', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_13
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-013
Title: AWS Security Groups allow internet traffic from internet to MSQL port (4333)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MSQL port (4333) to the internet. It is recommended that Global permission to access the well known services MSQL port (4333) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_4333
- id : PR-AWS-TRF-SG-013

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT14                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_eks_cluster', 'aws_iam_role', 'aws_security_group_rule', 'aws_iam_role_policy_attachment', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_13
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-013
Title: AWS Security Groups allow internet traffic from internet to MSQL port (4333)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MSQL port (4333) to the internet. It is recommended that Global permission to access the well known services MSQL port (4333) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_4333
- id : PR-AWS-TRF-SG-013

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_instance', 'aws_route_table_association', 'aws_internet_gateway', 'aws_elb', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_13
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-013
Title: AWS Security Groups allow internet traffic from internet to MSQL port (4333)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MSQL port (4333) to the internet. It is recommended that Global permission to access the well known services MSQL port (4333) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_4333
- id : PR-AWS-TRF-SG-013

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT23                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_13
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-013
Title: AWS Security Groups allow internet traffic from internet to MSQL port (4333)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MSQL port (4333) to the internet. It is recommended that Global permission to access the well known services MSQL port (4333) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_4333
- id : PR-AWS-TRF-SG-013

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT24                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_route_table_association', 'aws_subnet', 'aws_route_table', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/subnets.tf'] |

- masterTestId: TEST_SECURITY_GROUP_13
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-013
Title: AWS Security Groups allow internet traffic from internet to MSQL port (4333)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MSQL port (4333) to the internet. It is recommended that Global permission to access the well known services MSQL port (4333) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_4333
- id : PR-AWS-TRF-SG-013

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_13
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-013
Title: AWS Security Groups allow internet traffic from internet to MSQL port (4333)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MSQL port (4333) to the internet. It is recommended that Global permission to access the well known services MSQL port (4333) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_4333
- id : PR-AWS-TRF-SG-013

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT28                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_route_table_association', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/regions.tf'] |

- masterTestId: TEST_SECURITY_GROUP_13
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-013
Title: AWS Security Groups allow internet traffic from internet to MSQL port (4333)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing MSQL port (4333) to the internet. It is recommended that Global permission to access the well known services MSQL port (4333) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_4333
- id : PR-AWS-TRF-SG-013

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT30                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg.tf'] |

- masterTestId: TEST_SECURITY_GROUP_13
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-013
Title: AWS Security Groups allow internet traffic from internet to MSQL port (4333)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing MSQL port (4333) to the internet. It is recommended that Global permission to access the well known services MSQL port (4333) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_4333
- id : PR-AWS-TRF-SG-013

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws_instance', 'aws_route', 'aws_internet_gateway', 'aws_elb', 'aws_vpc', 'aws_key_pair', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_13
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-014
Title: AWS Security Groups allow internet traffic from internet to CIFS port (445)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing CIFS port (445) to the internet. It is recommended that Global permission to access the well known services CIFS port (445) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_445
- id : PR-AWS-TRF-SG-014

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group', 'aws_security_group']                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_14
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-014
Title: AWS Security Groups allow internet traffic from internet to CIFS port (445)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing CIFS port (445) to the internet. It is recommended that Global permission to access the well known services CIFS port (445) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_445
- id : PR-AWS-TRF-SG-014

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT12                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_iam_role', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_internet_gateway', 'aws_iam_instance_profile', 'aws_vpc', 'aws_alb_listener', 'aws_autoscaling_group', 'aws_alb_target_group', 'aws_alb', 'aws_route_table', 'aws_ecs_task_definition', 'aws_launch_configuration', 'aws_iam_role_policy', 'aws_subnet', 'aws_ecs_service', 'aws_ecs_cluster', 'aws_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_SECURITY_GROUP_14
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-014
Title: AWS Security Groups allow internet traffic from internet to CIFS port (445)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing CIFS port (445) to the internet. It is recommended that Global permission to access the well known services CIFS port (445) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_445
- id : PR-AWS-TRF-SG-014

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT13                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_eip', 'aws_instance', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_14
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-014
Title: AWS Security Groups allow internet traffic from internet to CIFS port (445)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing CIFS port (445) to the internet. It is recommended that Global permission to access the well known services CIFS port (445) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_445
- id : PR-AWS-TRF-SG-014

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT14                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_eks_cluster', 'aws_iam_role', 'aws_security_group_rule', 'aws_iam_role_policy_attachment', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_14
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-014
Title: AWS Security Groups allow internet traffic from internet to CIFS port (445)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing CIFS port (445) to the internet. It is recommended that Global permission to access the well known services CIFS port (445) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_445
- id : PR-AWS-TRF-SG-014

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_instance', 'aws_route_table_association', 'aws_internet_gateway', 'aws_elb', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_14
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-014
Title: AWS Security Groups allow internet traffic from internet to CIFS port (445)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing CIFS port (445) to the internet. It is recommended that Global permission to access the well known services CIFS port (445) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_445
- id : PR-AWS-TRF-SG-014

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT23                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_14
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-014
Title: AWS Security Groups allow internet traffic from internet to CIFS port (445)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing CIFS port (445) to the internet. It is recommended that Global permission to access the well known services CIFS port (445) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_445
- id : PR-AWS-TRF-SG-014

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT24                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_route_table_association', 'aws_subnet', 'aws_route_table', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/subnets.tf'] |

- masterTestId: TEST_SECURITY_GROUP_14
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-014
Title: AWS Security Groups allow internet traffic from internet to CIFS port (445)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing CIFS port (445) to the internet. It is recommended that Global permission to access the well known services CIFS port (445) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_445
- id : PR-AWS-TRF-SG-014

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_14
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-014
Title: AWS Security Groups allow internet traffic from internet to CIFS port (445)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing CIFS port (445) to the internet. It is recommended that Global permission to access the well known services CIFS port (445) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_445
- id : PR-AWS-TRF-SG-014

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT28                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_route_table_association', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/regions.tf'] |

- masterTestId: TEST_SECURITY_GROUP_14
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-014
Title: AWS Security Groups allow internet traffic from internet to CIFS port (445)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing CIFS port (445) to the internet. It is recommended that Global permission to access the well known services CIFS port (445) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_445
- id : PR-AWS-TRF-SG-014

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT30                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg.tf'] |

- masterTestId: TEST_SECURITY_GROUP_14
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-014
Title: AWS Security Groups allow internet traffic from internet to CIFS port (445)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing CIFS port (445) to the internet. It is recommended that Global permission to access the well known services CIFS port (445) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_445
- id : PR-AWS-TRF-SG-014

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws_instance', 'aws_route', 'aws_internet_gateway', 'aws_elb', 'aws_vpc', 'aws_key_pair', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_14
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-015
Title: AWS Security Groups allow internet traffic from internet to DNS port (53)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing DNS port (53) to the internet. It is recommended that Global permission to access the well known services DNS port (53) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_53
- id : PR-AWS-TRF-SG-015

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group', 'aws_security_group']                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_15
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-015
Title: AWS Security Groups allow internet traffic from internet to DNS port (53)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing DNS port (53) to the internet. It is recommended that Global permission to access the well known services DNS port (53) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_53
- id : PR-AWS-TRF-SG-015

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT12                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_iam_role', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_internet_gateway', 'aws_iam_instance_profile', 'aws_vpc', 'aws_alb_listener', 'aws_autoscaling_group', 'aws_alb_target_group', 'aws_alb', 'aws_route_table', 'aws_ecs_task_definition', 'aws_launch_configuration', 'aws_iam_role_policy', 'aws_subnet', 'aws_ecs_service', 'aws_ecs_cluster', 'aws_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_SECURITY_GROUP_15
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-015
Title: AWS Security Groups allow internet traffic from internet to DNS port (53)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing DNS port (53) to the internet. It is recommended that Global permission to access the well known services DNS port (53) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_53
- id : PR-AWS-TRF-SG-015

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT13                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_eip', 'aws_instance', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_15
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-015
Title: AWS Security Groups allow internet traffic from internet to DNS port (53)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing DNS port (53) to the internet. It is recommended that Global permission to access the well known services DNS port (53) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_53
- id : PR-AWS-TRF-SG-015

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT14                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_eks_cluster', 'aws_iam_role', 'aws_security_group_rule', 'aws_iam_role_policy_attachment', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_15
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-015
Title: AWS Security Groups allow internet traffic from internet to DNS port (53)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing DNS port (53) to the internet. It is recommended that Global permission to access the well known services DNS port (53) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_53
- id : PR-AWS-TRF-SG-015

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_instance', 'aws_route_table_association', 'aws_internet_gateway', 'aws_elb', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_15
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-015
Title: AWS Security Groups allow internet traffic from internet to DNS port (53)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing DNS port (53) to the internet. It is recommended that Global permission to access the well known services DNS port (53) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_53
- id : PR-AWS-TRF-SG-015

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT23                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_15
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-015
Title: AWS Security Groups allow internet traffic from internet to DNS port (53)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing DNS port (53) to the internet. It is recommended that Global permission to access the well known services DNS port (53) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_53
- id : PR-AWS-TRF-SG-015

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT24                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_route_table_association', 'aws_subnet', 'aws_route_table', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/subnets.tf'] |

- masterTestId: TEST_SECURITY_GROUP_15
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-015
Title: AWS Security Groups allow internet traffic from internet to DNS port (53)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing DNS port (53) to the internet. It is recommended that Global permission to access the well known services DNS port (53) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_53
- id : PR-AWS-TRF-SG-015

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_15
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-015
Title: AWS Security Groups allow internet traffic from internet to DNS port (53)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing DNS port (53) to the internet. It is recommended that Global permission to access the well known services DNS port (53) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_53
- id : PR-AWS-TRF-SG-015

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT28                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_route_table_association', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/regions.tf'] |

- masterTestId: TEST_SECURITY_GROUP_15
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-015
Title: AWS Security Groups allow internet traffic from internet to DNS port (53)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing DNS port (53) to the internet. It is recommended that Global permission to access the well known services DNS port (53) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_53
- id : PR-AWS-TRF-SG-015

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT30                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg.tf'] |

- masterTestId: TEST_SECURITY_GROUP_15
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-015
Title: AWS Security Groups allow internet traffic from internet to DNS port (53)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing DNS port (53) to the internet. It is recommended that Global permission to access the well known services DNS port (53) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_53
- id : PR-AWS-TRF-SG-015

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws_instance', 'aws_route', 'aws_internet_gateway', 'aws_elb', 'aws_vpc', 'aws_key_pair', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_15
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-016
Title: AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing PostgreSQL port (5432) to the internet. It is recommended that Global permission to access the well known services PostgreSQL port (5432) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5432
- id : PR-AWS-TRF-SG-016

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group', 'aws_security_group']                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_16
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-016
Title: AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing PostgreSQL port (5432) to the internet. It is recommended that Global permission to access the well known services PostgreSQL port (5432) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5432
- id : PR-AWS-TRF-SG-016

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT12                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_iam_role', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_internet_gateway', 'aws_iam_instance_profile', 'aws_vpc', 'aws_alb_listener', 'aws_autoscaling_group', 'aws_alb_target_group', 'aws_alb', 'aws_route_table', 'aws_ecs_task_definition', 'aws_launch_configuration', 'aws_iam_role_policy', 'aws_subnet', 'aws_ecs_service', 'aws_ecs_cluster', 'aws_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_SECURITY_GROUP_16
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-016
Title: AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing PostgreSQL port (5432) to the internet. It is recommended that Global permission to access the well known services PostgreSQL port (5432) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5432
- id : PR-AWS-TRF-SG-016

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT13                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_eip', 'aws_instance', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_16
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-016
Title: AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing PostgreSQL port (5432) to the internet. It is recommended that Global permission to access the well known services PostgreSQL port (5432) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5432
- id : PR-AWS-TRF-SG-016

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT14                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_eks_cluster', 'aws_iam_role', 'aws_security_group_rule', 'aws_iam_role_policy_attachment', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_16
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-016
Title: AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing PostgreSQL port (5432) to the internet. It is recommended that Global permission to access the well known services PostgreSQL port (5432) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5432
- id : PR-AWS-TRF-SG-016

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_instance', 'aws_route_table_association', 'aws_internet_gateway', 'aws_elb', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_16
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-016
Title: AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing PostgreSQL port (5432) to the internet. It is recommended that Global permission to access the well known services PostgreSQL port (5432) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5432
- id : PR-AWS-TRF-SG-016

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT23                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_16
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-016
Title: AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing PostgreSQL port (5432) to the internet. It is recommended that Global permission to access the well known services PostgreSQL port (5432) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5432
- id : PR-AWS-TRF-SG-016

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT24                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_route_table_association', 'aws_subnet', 'aws_route_table', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/subnets.tf'] |

- masterTestId: TEST_SECURITY_GROUP_16
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-016
Title: AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing PostgreSQL port (5432) to the internet. It is recommended that Global permission to access the well known services PostgreSQL port (5432) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5432
- id : PR-AWS-TRF-SG-016

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_16
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-016
Title: AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing PostgreSQL port (5432) to the internet. It is recommended that Global permission to access the well known services PostgreSQL port (5432) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5432
- id : PR-AWS-TRF-SG-016

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT28                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_route_table_association', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/regions.tf'] |

- masterTestId: TEST_SECURITY_GROUP_16
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-016
Title: AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing PostgreSQL port (5432) to the internet. It is recommended that Global permission to access the well known services PostgreSQL port (5432) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5432
- id : PR-AWS-TRF-SG-016

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT30                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg.tf'] |

- masterTestId: TEST_SECURITY_GROUP_16
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-016
Title: AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing PostgreSQL port (5432) to the internet. It is recommended that Global permission to access the well known services PostgreSQL port (5432) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5432
- id : PR-AWS-TRF-SG-016

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws_instance', 'aws_route', 'aws_internet_gateway', 'aws_elb', 'aws_vpc', 'aws_key_pair', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_16
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-017
Title: AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Listener port (5500) to the internet. It is recommended that Global permission to access the well known services VNC Listener port (5500) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5500
- id : PR-AWS-TRF-SG-017

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group', 'aws_security_group']                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_17
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-017
Title: AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Listener port (5500) to the internet. It is recommended that Global permission to access the well known services VNC Listener port (5500) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5500
- id : PR-AWS-TRF-SG-017

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT12                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_iam_role', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_internet_gateway', 'aws_iam_instance_profile', 'aws_vpc', 'aws_alb_listener', 'aws_autoscaling_group', 'aws_alb_target_group', 'aws_alb', 'aws_route_table', 'aws_ecs_task_definition', 'aws_launch_configuration', 'aws_iam_role_policy', 'aws_subnet', 'aws_ecs_service', 'aws_ecs_cluster', 'aws_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_SECURITY_GROUP_17
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-017
Title: AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Listener port (5500) to the internet. It is recommended that Global permission to access the well known services VNC Listener port (5500) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5500
- id : PR-AWS-TRF-SG-017

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT13                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_eip', 'aws_instance', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_17
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-017
Title: AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Listener port (5500) to the internet. It is recommended that Global permission to access the well known services VNC Listener port (5500) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5500
- id : PR-AWS-TRF-SG-017

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT14                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_eks_cluster', 'aws_iam_role', 'aws_security_group_rule', 'aws_iam_role_policy_attachment', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_17
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-017
Title: AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Listener port (5500) to the internet. It is recommended that Global permission to access the well known services VNC Listener port (5500) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5500
- id : PR-AWS-TRF-SG-017

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_instance', 'aws_route_table_association', 'aws_internet_gateway', 'aws_elb', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_17
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-017
Title: AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Listener port (5500) to the internet. It is recommended that Global permission to access the well known services VNC Listener port (5500) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5500
- id : PR-AWS-TRF-SG-017

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT23                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_17
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-017
Title: AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Listener port (5500) to the internet. It is recommended that Global permission to access the well known services VNC Listener port (5500) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5500
- id : PR-AWS-TRF-SG-017

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT24                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_route_table_association', 'aws_subnet', 'aws_route_table', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/subnets.tf'] |

- masterTestId: TEST_SECURITY_GROUP_17
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-017
Title: AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Listener port (5500) to the internet. It is recommended that Global permission to access the well known services VNC Listener port (5500) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5500
- id : PR-AWS-TRF-SG-017

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_17
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-017
Title: AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Listener port (5500) to the internet. It is recommended that Global permission to access the well known services VNC Listener port (5500) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5500
- id : PR-AWS-TRF-SG-017

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT28                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_route_table_association', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/regions.tf'] |

- masterTestId: TEST_SECURITY_GROUP_17
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-017
Title: AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing VNC Listener port (5500) to the internet. It is recommended that Global permission to access the well known services VNC Listener port (5500) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5500
- id : PR-AWS-TRF-SG-017

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT30                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg.tf'] |

- masterTestId: TEST_SECURITY_GROUP_17
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-017
Title: AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Listener port (5500) to the internet. It is recommended that Global permission to access the well known services VNC Listener port (5500) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5500
- id : PR-AWS-TRF-SG-017

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws_instance', 'aws_route', 'aws_internet_gateway', 'aws_elb', 'aws_vpc', 'aws_key_pair', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_17
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-018
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-TRF-SG-018

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group', 'aws_security_group']                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-018
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-TRF-SG-018

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT12                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_iam_role', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_internet_gateway', 'aws_iam_instance_profile', 'aws_vpc', 'aws_alb_listener', 'aws_autoscaling_group', 'aws_alb_target_group', 'aws_alb', 'aws_route_table', 'aws_ecs_task_definition', 'aws_launch_configuration', 'aws_iam_role_policy', 'aws_subnet', 'aws_ecs_service', 'aws_ecs_cluster', 'aws_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-018
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-TRF-SG-018

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT13                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_eip', 'aws_instance', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-018
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-TRF-SG-018

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT14                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_eks_cluster', 'aws_iam_role', 'aws_security_group_rule', 'aws_iam_role_policy_attachment', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-018
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-TRF-SG-018

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_instance', 'aws_route_table_association', 'aws_internet_gateway', 'aws_elb', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-018
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-TRF-SG-018

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT23                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-018
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-TRF-SG-018

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT24                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_route_table_association', 'aws_subnet', 'aws_route_table', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/subnets.tf'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-018
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-TRF-SG-018

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/security_group.tf'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-018
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-TRF-SG-018

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT28                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_route_table_association', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/regions.tf'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-018
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-TRF-SG-018

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT30                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_security_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg.tf'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-018
Title: AWS Security Groups allow internet traffic from internet to VNC Server port (5900)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5900
- id : PR-AWS-TRF-SG-018

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws_instance', 'aws_route', 'aws_internet_gateway', 'aws_elb', 'aws_vpc', 'aws_key_pair', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_18
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-019
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-TRF-SG-019

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group', 'aws_security_group']                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                          |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-019
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-TRF-SG-019

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT12                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_iam_role', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_internet_gateway', 'aws_iam_instance_profile', 'aws_vpc', 'aws_alb_listener', 'aws_autoscaling_group', 'aws_alb_target_group', 'aws_alb', 'aws_route_table', 'aws_ecs_task_definition', 'aws_launch_configuration', 'aws_iam_role_policy', 'aws_subnet', 'aws_ecs_service', 'aws_ecs_cluster', 'aws_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                          |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-019
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-TRF-SG-019

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT13                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_eip', 'aws_instance', 'aws_security_group']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_19
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'SOC 2'] |
| service    | ['terraform']                                                          |
----------------------------------------------------------------

