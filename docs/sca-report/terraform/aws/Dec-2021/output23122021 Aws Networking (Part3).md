# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AWS (Dec 2021)

## All Services

#### Compute: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Dec-2021/output23122021%20Aws%20Compute.md
#### Data Store: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Dec-2021/output23122021%20Aws%20DataStore.md
#### Management: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Dec-2021/output23122021%20Aws%20Management.md
#### Networking (Part1): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Dec-2021/output23122021%20Aws%20Networking%20(Part1).md
#### Networking (Part2): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Dec-2021/output23122021%20Aws%20Networking%20(Part2).md
#### Networking (Part3): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Dec-2021/output23122021%20Aws%20Networking%20(Part3).md
#### Security: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Dec-2021/output11232021%20Aws%20Security.md

## Terraform Aws Networking (Part3) Services

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

### Test ID - PR-AWS-TRF-SG-019
Title: AWS Default Security Group does not restrict all traffic\
Test Result: **passed**\
Description : This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.\

#### Test Details
- eval: data.rule.port_all
- id : PR-AWS-TRF-SG-019

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
| id            | TRF_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_instance', 'aws_route_table_association', 'aws_internet_gateway', 'aws_elb', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_security_group']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

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


### Test ID - PR-AWS-TRF-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-TRF-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
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


### Test ID - PR-AWS-TRF-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-TRF-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
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


### Test ID - PR-AWS-TRF-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-TRF-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
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


### Test ID - PR-AWS-TRF-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-TRF-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
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


### Test ID - PR-AWS-TRF-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-TRF-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
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


### Test ID - PR-AWS-TRF-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-TRF-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
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


### Test ID - PR-AWS-TRF-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-TRF-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
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


### Test ID - PR-AWS-TRF-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-TRF-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
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


### Test ID - PR-AWS-TRF-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-TRF-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
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


### Test ID - PR-AWS-TRF-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-TRF-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
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


### Test ID - PR-AWS-TRF-SG-020
Title: AWS Security Groups with Inbound rule overly permissive to All Traffic\
Test Result: **passed**\
Description : This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.\

#### Test Details
- eval: data.rule.port_proto_all
- id : PR-AWS-TRF-SG-020

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

- masterTestId: TEST_SECURITY_GROUP_20
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


### Test ID - PR-AWS-TRF-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-TRF-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
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


### Test ID - PR-AWS-TRF-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-TRF-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
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


### Test ID - PR-AWS-TRF-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-TRF-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
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


### Test ID - PR-AWS-TRF-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-TRF-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
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


### Test ID - PR-AWS-TRF-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-TRF-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
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


### Test ID - PR-AWS-TRF-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-TRF-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
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


### Test ID - PR-AWS-TRF-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-TRF-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
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


### Test ID - PR-AWS-TRF-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-TRF-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
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


### Test ID - PR-AWS-TRF-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-TRF-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
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


### Test ID - PR-AWS-TRF-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-TRF-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
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


### Test ID - PR-AWS-TRF-SG-021
Title: AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_69
- id : PR-AWS-TRF-SG-021

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

- masterTestId: TEST_SECURITY_GROUP_21
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


### Test ID - PR-AWS-TRF-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-TRF-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
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


### Test ID - PR-AWS-TRF-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-TRF-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
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


### Test ID - PR-AWS-TRF-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-TRF-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
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


### Test ID - PR-AWS-TRF-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **passed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-TRF-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
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


### Test ID - PR-AWS-TRF-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-TRF-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
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


### Test ID - PR-AWS-TRF-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-TRF-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
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


### Test ID - PR-AWS-TRF-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-TRF-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
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


### Test ID - PR-AWS-TRF-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-TRF-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
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


### Test ID - PR-AWS-TRF-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-TRF-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
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


### Test ID - PR-AWS-TRF-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **passed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-TRF-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
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


### Test ID - PR-AWS-TRF-SG-022
Title: Ensure AWS resources that support tags have Tags\
Test Result: **failed**\
Description : Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.\

#### Test Details
- eval: data.rule.sg_tag
- id : PR-AWS-TRF-SG-022

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

- masterTestId: TEST_SECURITY_GROUP_22
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


### Test ID - PR-AWS-TRF-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **passed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-TRF-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
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


### Test ID - PR-AWS-TRF-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **passed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-TRF-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
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


### Test ID - PR-AWS-TRF-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **passed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-TRF-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
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


### Test ID - PR-AWS-TRF-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **passed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-TRF-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
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


### Test ID - PR-AWS-TRF-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **passed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-TRF-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
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


### Test ID - PR-AWS-TRF-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **passed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-TRF-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
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


### Test ID - PR-AWS-TRF-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **passed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-TRF-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
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


### Test ID - PR-AWS-TRF-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **passed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-TRF-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
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


### Test ID - PR-AWS-TRF-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **passed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-TRF-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
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


### Test ID - PR-AWS-TRF-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **passed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-TRF-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
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


### Test ID - PR-AWS-TRF-SG-023
Title: Ensure every Security Group rule contains a description\
Test Result: **passed**\
Description : We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.\

#### Test Details
- eval: data.rule.sg_description_absent
- id : PR-AWS-TRF-SG-023

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

- masterTestId: TEST_SECURITY_GROUP_23
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


### Test ID - PR-AWS-TRF-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-TRF-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
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


### Test ID - PR-AWS-TRF-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-TRF-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
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


### Test ID - PR-AWS-TRF-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-TRF-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
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


### Test ID - PR-AWS-TRF-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-TRF-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
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


### Test ID - PR-AWS-TRF-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-TRF-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
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


### Test ID - PR-AWS-TRF-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-TRF-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
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


### Test ID - PR-AWS-TRF-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-TRF-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
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


### Test ID - PR-AWS-TRF-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-TRF-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
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


### Test ID - PR-AWS-TRF-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-TRF-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
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


### Test ID - PR-AWS-TRF-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-TRF-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
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


### Test ID - PR-AWS-TRF-SG-024
Title: AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_9300
- id : PR-AWS-TRF-SG-024

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

- masterTestId: TEST_SECURITY_GROUP_24
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


### Test ID - PR-AWS-TRF-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-TRF-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
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


### Test ID - PR-AWS-TRF-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-TRF-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
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


### Test ID - PR-AWS-TRF-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-TRF-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
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


### Test ID - PR-AWS-TRF-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-TRF-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
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


### Test ID - PR-AWS-TRF-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-TRF-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
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


### Test ID - PR-AWS-TRF-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-TRF-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
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


### Test ID - PR-AWS-TRF-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-TRF-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
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


### Test ID - PR-AWS-TRF-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-TRF-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
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


### Test ID - PR-AWS-TRF-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-TRF-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
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


### Test ID - PR-AWS-TRF-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-TRF-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
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


### Test ID - PR-AWS-TRF-SG-025
Title: AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5601
- id : PR-AWS-TRF-SG-025

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

- masterTestId: TEST_SECURITY_GROUP_25
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


### Test ID - PR-AWS-TRF-SG-026
Title: AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing etcd-client Protocol Port (2379) to the internet. It is recommended that Global permission to access the well known services etcd-client Protocol Port (2379) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_2379
- id : PR-AWS-TRF-SG-026

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

- masterTestId: TEST_SECURITY_GROUP_26
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


### Test ID - PR-AWS-TRF-SG-026
Title: AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing etcd-client Protocol Port (2379) to the internet. It is recommended that Global permission to access the well known services etcd-client Protocol Port (2379) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_2379
- id : PR-AWS-TRF-SG-026

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

- masterTestId: TEST_SECURITY_GROUP_26
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


### Test ID - PR-AWS-TRF-SG-026
Title: AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing etcd-client Protocol Port (2379) to the internet. It is recommended that Global permission to access the well known services etcd-client Protocol Port (2379) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_2379
- id : PR-AWS-TRF-SG-026

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

- masterTestId: TEST_SECURITY_GROUP_26
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


### Test ID - PR-AWS-TRF-SG-026
Title: AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing etcd-client Protocol Port (2379) to the internet. It is recommended that Global permission to access the well known services etcd-client Protocol Port (2379) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_2379
- id : PR-AWS-TRF-SG-026

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

- masterTestId: TEST_SECURITY_GROUP_26
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


### Test ID - PR-AWS-TRF-SG-026
Title: AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing etcd-client Protocol Port (2379) to the internet. It is recommended that Global permission to access the well known services etcd-client Protocol Port (2379) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_2379
- id : PR-AWS-TRF-SG-026

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

- masterTestId: TEST_SECURITY_GROUP_26
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


### Test ID - PR-AWS-TRF-SG-026
Title: AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing etcd-client Protocol Port (2379) to the internet. It is recommended that Global permission to access the well known services etcd-client Protocol Port (2379) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_2379
- id : PR-AWS-TRF-SG-026

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

- masterTestId: TEST_SECURITY_GROUP_26
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


### Test ID - PR-AWS-TRF-SG-026
Title: AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing etcd-client Protocol Port (2379) to the internet. It is recommended that Global permission to access the well known services etcd-client Protocol Port (2379) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_2379
- id : PR-AWS-TRF-SG-026

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

- masterTestId: TEST_SECURITY_GROUP_26
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


### Test ID - PR-AWS-TRF-SG-026
Title: AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing etcd-client Protocol Port (2379) to the internet. It is recommended that Global permission to access the well known services etcd-client Protocol Port (2379) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_2379
- id : PR-AWS-TRF-SG-026

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

- masterTestId: TEST_SECURITY_GROUP_26
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


### Test ID - PR-AWS-TRF-SG-026
Title: AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing etcd-client Protocol Port (2379) to the internet. It is recommended that Global permission to access the well known services etcd-client Protocol Port (2379) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_2379
- id : PR-AWS-TRF-SG-026

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

- masterTestId: TEST_SECURITY_GROUP_26
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


### Test ID - PR-AWS-TRF-SG-026
Title: AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing etcd-client Protocol Port (2379) to the internet. It is recommended that Global permission to access the well known services etcd-client Protocol Port (2379) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_2379
- id : PR-AWS-TRF-SG-026

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

- masterTestId: TEST_SECURITY_GROUP_26
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


### Test ID - PR-AWS-TRF-SG-026
Title: AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing etcd-client Protocol Port (2379) to the internet. It is recommended that Global permission to access the well known services etcd-client Protocol Port (2379) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_2379
- id : PR-AWS-TRF-SG-026

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

- masterTestId: TEST_SECURITY_GROUP_26
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


### Test ID - PR-AWS-TRF-SG-027
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5986
- id : PR-AWS-TRF-SG-027

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

- masterTestId: TEST_SECURITY_GROUP_27
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


### Test ID - PR-AWS-TRF-SG-027
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5986
- id : PR-AWS-TRF-SG-027

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

- masterTestId: TEST_SECURITY_GROUP_27
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


### Test ID - PR-AWS-TRF-SG-027
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5986
- id : PR-AWS-TRF-SG-027

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

- masterTestId: TEST_SECURITY_GROUP_27
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


### Test ID - PR-AWS-TRF-SG-027
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5986
- id : PR-AWS-TRF-SG-027

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

- masterTestId: TEST_SECURITY_GROUP_27
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


### Test ID - PR-AWS-TRF-SG-027
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5986
- id : PR-AWS-TRF-SG-027

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

- masterTestId: TEST_SECURITY_GROUP_27
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


### Test ID - PR-AWS-TRF-SG-027
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5986
- id : PR-AWS-TRF-SG-027

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

- masterTestId: TEST_SECURITY_GROUP_27
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


### Test ID - PR-AWS-TRF-SG-027
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5986
- id : PR-AWS-TRF-SG-027

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

- masterTestId: TEST_SECURITY_GROUP_27
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


### Test ID - PR-AWS-TRF-SG-027
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5986
- id : PR-AWS-TRF-SG-027

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

- masterTestId: TEST_SECURITY_GROUP_27
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


### Test ID - PR-AWS-TRF-SG-027
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5986
- id : PR-AWS-TRF-SG-027

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

- masterTestId: TEST_SECURITY_GROUP_27
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


### Test ID - PR-AWS-TRF-SG-027
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5986
- id : PR-AWS-TRF-SG-027

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

- masterTestId: TEST_SECURITY_GROUP_27
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


### Test ID - PR-AWS-TRF-SG-027
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5986
- id : PR-AWS-TRF-SG-027

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

- masterTestId: TEST_SECURITY_GROUP_27
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


### Test ID - PR-AWS-TRF-SG-028
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5985
- id : PR-AWS-TRF-SG-028

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

- masterTestId: TEST_SECURITY_GROUP_28
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


### Test ID - PR-AWS-TRF-SG-028
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5985
- id : PR-AWS-TRF-SG-028

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

- masterTestId: TEST_SECURITY_GROUP_28
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


### Test ID - PR-AWS-TRF-SG-028
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5985
- id : PR-AWS-TRF-SG-028

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

- masterTestId: TEST_SECURITY_GROUP_28
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


### Test ID - PR-AWS-TRF-SG-028
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5985
- id : PR-AWS-TRF-SG-028

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

- masterTestId: TEST_SECURITY_GROUP_28
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


### Test ID - PR-AWS-TRF-SG-028
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5985
- id : PR-AWS-TRF-SG-028

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

- masterTestId: TEST_SECURITY_GROUP_28
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


### Test ID - PR-AWS-TRF-SG-028
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5985
- id : PR-AWS-TRF-SG-028

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

- masterTestId: TEST_SECURITY_GROUP_28
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


### Test ID - PR-AWS-TRF-SG-028
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5985
- id : PR-AWS-TRF-SG-028

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

- masterTestId: TEST_SECURITY_GROUP_28
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


### Test ID - PR-AWS-TRF-SG-028
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5985
- id : PR-AWS-TRF-SG-028

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

- masterTestId: TEST_SECURITY_GROUP_28
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


### Test ID - PR-AWS-TRF-SG-028
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5985
- id : PR-AWS-TRF-SG-028

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

- masterTestId: TEST_SECURITY_GROUP_28
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


### Test ID - PR-AWS-TRF-SG-028
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5985
- id : PR-AWS-TRF-SG-028

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

- masterTestId: TEST_SECURITY_GROUP_28
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


### Test ID - PR-AWS-TRF-SG-028
Title: AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_5985
- id : PR-AWS-TRF-SG-028

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

- masterTestId: TEST_SECURITY_GROUP_28
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


### Test ID - PR-AWS-TRF-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-TRF-SG-029

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

- masterTestId: TEST_SECURITY_GROUP_29
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


### Test ID - PR-AWS-TRF-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-TRF-SG-029

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

- masterTestId: TEST_SECURITY_GROUP_29
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


### Test ID - PR-AWS-TRF-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-TRF-SG-029

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

- masterTestId: TEST_SECURITY_GROUP_29
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


### Test ID - PR-AWS-TRF-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-TRF-SG-029

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

- masterTestId: TEST_SECURITY_GROUP_29
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


### Test ID - PR-AWS-TRF-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-TRF-SG-029

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

- masterTestId: TEST_SECURITY_GROUP_29
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


### Test ID - PR-AWS-TRF-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-TRF-SG-029

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

- masterTestId: TEST_SECURITY_GROUP_29
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


### Test ID - PR-AWS-TRF-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-TRF-SG-029

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

- masterTestId: TEST_SECURITY_GROUP_29
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


### Test ID - PR-AWS-TRF-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-TRF-SG-029

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

- masterTestId: TEST_SECURITY_GROUP_29
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


### Test ID - PR-AWS-TRF-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-TRF-SG-029

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

- masterTestId: TEST_SECURITY_GROUP_29
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


### Test ID - PR-AWS-TRF-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-TRF-SG-029

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

- masterTestId: TEST_SECURITY_GROUP_29
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


### Test ID - PR-AWS-TRF-SG-029
Title: AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1270
- id : PR-AWS-TRF-SG-029

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

- masterTestId: TEST_SECURITY_GROUP_29
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

