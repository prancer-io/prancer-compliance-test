# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AWS (Jan 2022)

## All Services

#### Compute: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Compute.md
#### Data Store: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20DataStore.md
#### Management: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Management.md
#### Networking (Part1): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Networking%20(Part1).md
#### Networking (Part2): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Networking%20(Part2).md
#### Networking (Part3): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Networking%20(Part3).md
#### Security: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Security.md

## Terraform Aws Compute Services

Source Repository: https://github.com/hashicorp/terraform-provider-aws

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform

## Compliance run Meta Data
| Title     | Description                      |
|:----------|:---------------------------------|
| timestamp | 1642967689008                    |
| snapshot  | master-snapshot_gen              |
| container | scenario-aws-terraform-hashicorp |
| test      | master-test.json                 |

## Results

### Test ID - PR-AWS-TRF-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-TRF-EC2-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT10                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_elb', 'aws_instance']                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/count/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/count/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/count/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-001
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-TRF-EC2-001

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
| resourceTypes | ['aws_security_group', 'aws_eip', 'aws_instance']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-001
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-TRF-EC2-001

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
| resourceTypes | ['aws_security_group', 'aws_vpc', 'aws_route_table', 'aws_route_table_association', 'aws_subnet', 'aws_lb_cookie_stickiness_policy', 'aws_instance', 'aws_internet_gateway', 'aws_elb']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-001
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-001
Title: AWS EC2 Instance IAM Role not enabled\
Test Result: **failed**\
Description : AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.\

#### Test Details
- eval: data.rule.ec2_iam_role
- id : PR-AWS-TRF-EC2-001

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
| resourceTypes | ['aws_security_group', 'aws_vpc', 'aws_key_pair', 'aws_route', 'aws_subnet', 'aws_instance', 'aws_internet_gateway', 'aws_elb']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-001
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-TRF-EC2-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT10                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_elb', 'aws_instance']                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/count/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/count/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/count/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['terraform']                    |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-TRF-EC2-002

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
| resourceTypes | ['aws_security_group', 'aws_eip', 'aws_instance']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['terraform']                    |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-TRF-EC2-002

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
| resourceTypes | ['aws_security_group', 'aws_vpc', 'aws_route_table', 'aws_route_table_association', 'aws_subnet', 'aws_lb_cookie_stickiness_policy', 'aws_instance', 'aws_internet_gateway', 'aws_elb']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['terraform']                    |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-002
Title: AWS EC2 instance is not configured with VPC\
Test Result: **passed**\
Description : This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.\

#### Test Details
- eval: data.rule.ec2_no_vpc
- id : PR-AWS-TRF-EC2-002

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
| resourceTypes | ['aws_security_group', 'aws_vpc', 'aws_key_pair', 'aws_route', 'aws_subnet', 'aws_instance', 'aws_internet_gateway', 'aws_elb']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Medium

tags
| Title      | Description                      |
|:-----------|:---------------------------------|
| cloud      | git                              |
| compliance | ['PCI-DSS', 'HIPAA', 'NIST 800'] |
| service    | ['terraform']                    |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-TRF-EC2-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT10                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_elb', 'aws_instance']                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/count/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/count/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/count/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['terraform']                  |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-TRF-EC2-003

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
| resourceTypes | ['aws_security_group', 'aws_eip', 'aws_instance']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['terraform']                  |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-TRF-EC2-003

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
| resourceTypes | ['aws_security_group', 'aws_vpc', 'aws_route_table', 'aws_route_table_association', 'aws_subnet', 'aws_lb_cookie_stickiness_policy', 'aws_instance', 'aws_internet_gateway', 'aws_elb']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['terraform']                  |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-003
Title: AWS EC2 instances with Public IP and associated with Security Groups have Internet Access\
Test Result: **passed**\
Description : This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.\

#### Test Details
- eval: data.rule.ec2_public_ip
- id : PR-AWS-TRF-EC2-003

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
| resourceTypes | ['aws_security_group', 'aws_vpc', 'aws_key_pair', 'aws_route', 'aws_subnet', 'aws_instance', 'aws_internet_gateway', 'aws_elb']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Low

tags
| Title      | Description                    |
|:-----------|:-------------------------------|
| cloud      | git                            |
| compliance | ['CIS', 'PCI-DSS', 'NIST 800'] |
| service    | ['terraform']                  |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable ebs_optimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-TRF-EC2-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT10                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_elb', 'aws_instance']                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/count/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/count/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/count/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-004
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Low

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable ebs_optimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-TRF-EC2-004

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
| resourceTypes | ['aws_security_group', 'aws_eip', 'aws_instance']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-004
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Low

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable ebs_optimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-TRF-EC2-004

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
| resourceTypes | ['aws_security_group', 'aws_vpc', 'aws_route_table', 'aws_route_table_association', 'aws_subnet', 'aws_lb_cookie_stickiness_policy', 'aws_instance', 'aws_internet_gateway', 'aws_elb']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-004
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Low

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-004
Title: Ensure that EC2 instace is EBS Optimized\
Test Result: **failed**\
Description : Enable ebs_optimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance\

#### Test Details
- eval: data.rule.ec2_ebs_optimized
- id : PR-AWS-TRF-EC2-004

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
| resourceTypes | ['aws_security_group', 'aws_vpc', 'aws_key_pair', 'aws_route', 'aws_subnet', 'aws_instance', 'aws_internet_gateway', 'aws_elb']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-004
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Low

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better Janisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-TRF-EC2-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT10                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_elb', 'aws_instance']                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/count/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/count/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/count/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-005
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['NIST 800']  |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better Janisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-TRF-EC2-005

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
| resourceTypes | ['aws_security_group', 'aws_eip', 'aws_instance']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-005
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['NIST 800']  |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better Janisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-TRF-EC2-005

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
| resourceTypes | ['aws_security_group', 'aws_vpc', 'aws_route_table', 'aws_route_table_association', 'aws_subnet', 'aws_lb_cookie_stickiness_policy', 'aws_instance', 'aws_internet_gateway', 'aws_elb']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-005
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['NIST 800']  |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EC2-005
Title: Ensure detailed monitoring is enabled for EC2 instances\
Test Result: **failed**\
Description : Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better Janisions on architecting and managing compute resources within your AWS account\

#### Test Details
- eval: data.rule.ec2_monitoring
- id : PR-AWS-TRF-EC2-005

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
| resourceTypes | ['aws_security_group', 'aws_vpc', 'aws_key_pair', 'aws_route', 'aws_subnet', 'aws_instance', 'aws_internet_gateway', 'aws_elb']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: PR-AWS-TRF-EC2-005
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['NIST 800']  |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ECS-001
Title: AWS ECS task definition elevated privileges enabled\
Test Result: **passed**\
Description : Ensure your ECS containers are not given elevated privileges on the host container instance. When the privileged parameter is true, the container is given elevated privileges on the host container instance (similar to the root user). This policy checks the security configuration of your task definition and alerts if elevated privileges are enabled. Note: This parameter is not supported for Windows containers or tasks using the Fargate launch type.\

#### Test Details
- eval: data.rule.ecs_task_evelated
- id : PR-AWS-TRF-ECS-001

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
| resourceTypes | ['aws_autoscaling_group', 'aws_security_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_route_table', 'aws_ecs_cluster', 'aws_route_table_association', 'aws_ecs_service', 'aws_ecs_task_definition', 'aws_iam_role', 'aws_cloudwatch_log_group', 'aws_alb', 'aws_subnet', 'aws_iam_instance_profile', 'aws_alb_listener', 'aws_launch_configuration', 'aws_internet_gateway', 'aws_alb_target_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: PR-AWS-TRF-ECS-001
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego)
- severity: High

tags
| Title      | Description                                                        |
|:-----------|:-------------------------------------------------------------------|
| cloud      | git                                                                |
| compliance | ['HITRUST', 'GDPR', 'NIST 800', 'PCI-DSS', 'CSA-CCM', 'ISO 27001'] |
| service    | ['terraform']                                                      |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ECS-002
Title: AWS ECS/Fargate task definition execution IAM Role not found\
Test Result: **failed**\
Description : The execution IAM Role is required by tasks to pull container images and publish container logs to Amazon CloudWatch on your behalf. This policy generates an alert if a task execution role is not found in your task definition.\

#### Test Details
- eval: data.rule.ecs_exec
- id : PR-AWS-TRF-ECS-002

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
| resourceTypes | ['aws_autoscaling_group', 'aws_security_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_route_table', 'aws_ecs_cluster', 'aws_route_table_association', 'aws_ecs_service', 'aws_ecs_task_definition', 'aws_iam_role', 'aws_cloudwatch_log_group', 'aws_alb', 'aws_subnet', 'aws_iam_instance_profile', 'aws_alb_listener', 'aws_launch_configuration', 'aws_internet_gateway', 'aws_alb_target_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: PR-AWS-TRF-ECS-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego)
- severity: Medium

tags
| Title      | Description                                                        |
|:-----------|:-------------------------------------------------------------------|
| cloud      | git                                                                |
| compliance | ['HITRUST', 'GDPR', 'NIST 800', 'PCI-DSS', 'CSA-CCM', 'ISO 27001'] |
| service    | ['terraform']                                                      |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ECS-003
Title: AWS ECS/ Fargate task definition root user found\
Test Result: **passed**\
Description : The user name to use inside the container should not be root. This policy generates an alert if root user is found in your container definition. The User parameter maps to User in the Create a container section of the Docker Remote API and the --user option to docker run Note: This parameter is not supported for Windows containers.\

#### Test Details
- eval: data.rule.ecs_root_user
- id : PR-AWS-TRF-ECS-003

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
| resourceTypes | ['aws_autoscaling_group', 'aws_security_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_route_table', 'aws_ecs_cluster', 'aws_route_table_association', 'aws_ecs_service', 'aws_ecs_task_definition', 'aws_iam_role', 'aws_cloudwatch_log_group', 'aws_alb', 'aws_subnet', 'aws_iam_instance_profile', 'aws_alb_listener', 'aws_launch_configuration', 'aws_internet_gateway', 'aws_alb_target_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: PR-AWS-TRF-ECS-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego)
- severity: High

tags
| Title      | Description                                                        |
|:-----------|:-------------------------------------------------------------------|
| cloud      | git                                                                |
| compliance | ['HITRUST', 'GDPR', 'NIST 800', 'PCI-DSS', 'CSA-CCM', 'ISO 27001'] |
| service    | ['terraform']                                                      |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ECS-004
Title: AWS ECS Task Definition readonlyRootFilesystem Not Enabled\
Test Result: **passed**\
Description : It is recommended that readonlyRootFilesystem is enabled for AWS ECS task definition. Please make sure your 'container_definitions' template has 'ReadonlyRootFilesystem' and is set to 'true'.\

#### Test Details
- eval: data.rule.ecs_root_filesystem
- id : PR-AWS-TRF-ECS-004

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
| resourceTypes | ['aws_autoscaling_group', 'aws_security_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_route_table', 'aws_ecs_cluster', 'aws_route_table_association', 'aws_ecs_service', 'aws_ecs_task_definition', 'aws_iam_role', 'aws_cloudwatch_log_group', 'aws_alb', 'aws_subnet', 'aws_iam_instance_profile', 'aws_alb_listener', 'aws_launch_configuration', 'aws_internet_gateway', 'aws_alb_target_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: PR-AWS-TRF-ECS-004
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ECS-005
Title: AWS ECS task definition resource limits not set.\
Test Result: **failed**\
Description : It is recommended that resource limits are set for AWS ECS task definition. Please make sure attributes 'Cpu' or 'Memory' exists and its value is not set to 0 under 'TaskDefinition' or 'ContainerDefinitions'.\

#### Test Details
- eval: data.rule.ecs_resource_limit
- id : PR-AWS-TRF-ECS-005

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
| resourceTypes | ['aws_autoscaling_group', 'aws_security_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_route_table', 'aws_ecs_cluster', 'aws_route_table_association', 'aws_ecs_service', 'aws_ecs_task_definition', 'aws_iam_role', 'aws_cloudwatch_log_group', 'aws_alb', 'aws_subnet', 'aws_iam_instance_profile', 'aws_alb_listener', 'aws_launch_configuration', 'aws_internet_gateway', 'aws_alb_target_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: PR-AWS-TRF-ECS-005
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ECS-006
Title: AWS ECS task definition logging not enabled.\
Test Result: **passed**\
Description : It is recommended that logging is enabled for AWS ECS task definition. Please make sure your 'TaskDefinition' template has 'logConfiguration' and 'logDriver' configured.\

#### Test Details
- eval: data.rule.ecs_logging
- id : PR-AWS-TRF-ECS-006

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
| resourceTypes | ['aws_autoscaling_group', 'aws_security_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_route_table', 'aws_ecs_cluster', 'aws_route_table_association', 'aws_ecs_service', 'aws_ecs_task_definition', 'aws_iam_role', 'aws_cloudwatch_log_group', 'aws_alb', 'aws_subnet', 'aws_iam_instance_profile', 'aws_alb_listener', 'aws_launch_configuration', 'aws_internet_gateway', 'aws_alb_target_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: PR-AWS-TRF-ECS-006
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['NIST 800']  |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ECS-007
Title: Ensure EFS volumes in ECS task definitions have encryption in transit enabled\
Test Result: **passed**\
Description : ECS task definitions that have volumes using EFS configuration should explicitly enable in transit encryption to prevent the risk of data loss due to interception.\

#### Test Details
- eval: data.rule.ecs_transit_enabled
- id : PR-AWS-TRF-ECS-007

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
| resourceTypes | ['aws_autoscaling_group', 'aws_security_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_route_table', 'aws_ecs_cluster', 'aws_route_table_association', 'aws_ecs_service', 'aws_ecs_task_definition', 'aws_iam_role', 'aws_cloudwatch_log_group', 'aws_alb', 'aws_subnet', 'aws_iam_instance_profile', 'aws_alb_listener', 'aws_launch_configuration', 'aws_internet_gateway', 'aws_alb_target_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: PR-AWS-TRF-ECS-007
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ECS-008
Title: Ensure container insights are enabled on ECS cluster\
Test Result: **failed**\
Description : Container Insights can be used to collect, aggregate, and summarize metrics and logs from containerized applications and microservices. They can also be extended to collect metrics at the cluster, task, and service levels. Using Container Insights allows you to monitor, troubleshoot, and set alarms for all your Amazon ECS resources. It provides a simple to use native and fully managed service for managing ECS issues.\

#### Test Details
- eval: data.rule.ecs_container_insight_enable
- id : PR-AWS-TRF-ECS-008

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
| resourceTypes | ['aws_autoscaling_group', 'aws_security_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_route_table', 'aws_ecs_cluster', 'aws_route_table_association', 'aws_ecs_service', 'aws_ecs_task_definition', 'aws_iam_role', 'aws_cloudwatch_log_group', 'aws_alb', 'aws_subnet', 'aws_iam_instance_profile', 'aws_alb_listener', 'aws_launch_configuration', 'aws_internet_gateway', 'aws_alb_target_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: PR-AWS-TRF-ECS-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ECS-009
Title: Ensure ECS Services and Task Set enable_execute_command property set to False\
Test Result: **passed**\
Description : If the enable_execute_command property is set to True on an ECS Service then any third person can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations.\

#### Test Details
- eval: data.rule.ecs_enable_execute_command
- id : PR-AWS-TRF-ECS-009

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
| resourceTypes | ['aws_autoscaling_group', 'aws_security_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_route_table', 'aws_ecs_cluster', 'aws_route_table_association', 'aws_ecs_service', 'aws_ecs_task_definition', 'aws_iam_role', 'aws_cloudwatch_log_group', 'aws_alb', 'aws_subnet', 'aws_iam_instance_profile', 'aws_alb_listener', 'aws_launch_configuration', 'aws_internet_gateway', 'aws_alb_target_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: PR-AWS-TRF-ECS-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ECS-010
Title: Ensure that ECS Service and Task Set network configuration disallows the assignment of public IPs\
Test Result: **passed**\
Description : Ensure that the ecs service and Task Set Network has set [AssignPublicIp/assign_public_ip] property is set to DISABLED else an Actor can exfiltrate data by associating ECS resources with non-ADATUM resources\

#### Test Details
- eval: data.rule.ecs_assign_public_ip
- id : PR-AWS-TRF-ECS-010

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
| resourceTypes | ['aws_autoscaling_group', 'aws_security_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_route_table', 'aws_ecs_cluster', 'aws_route_table_association', 'aws_ecs_service', 'aws_ecs_task_definition', 'aws_iam_role', 'aws_cloudwatch_log_group', 'aws_alb', 'aws_subnet', 'aws_iam_instance_profile', 'aws_alb_listener', 'aws_launch_configuration', 'aws_internet_gateway', 'aws_alb_target_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: PR-AWS-TRF-ECS-010
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ECS-011
Title: Ensure that ECS services and Task Sets are launched as Fargate type\
Test Result: **failed**\
Description : Ensure that ECS services and Task Sets are launched as Fargate type else Actor can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations.\

#### Test Details
- eval: data.rule.ecs_launch_type
- id : PR-AWS-TRF-ECS-011

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
| resourceTypes | ['aws_autoscaling_group', 'aws_security_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_route_table', 'aws_ecs_cluster', 'aws_route_table_association', 'aws_ecs_service', 'aws_ecs_task_definition', 'aws_iam_role', 'aws_cloudwatch_log_group', 'aws_alb', 'aws_subnet', 'aws_iam_instance_profile', 'aws_alb_listener', 'aws_launch_configuration', 'aws_internet_gateway', 'aws_alb_target_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: PR-AWS-TRF-ECS-011
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ECS-012
Title: Value(s) of subnets attached to aws ecs service subnets are vended\
Test Result: **passed**\
Description : Value(s) of subnets attached to aws ecs service subnets are vended else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.\

#### Test Details
- eval: data.rule.ecs_subnet
- id : PR-AWS-TRF-ECS-012

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
| resourceTypes | ['aws_autoscaling_group', 'aws_security_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_route_table', 'aws_ecs_cluster', 'aws_route_table_association', 'aws_ecs_service', 'aws_ecs_task_definition', 'aws_iam_role', 'aws_cloudwatch_log_group', 'aws_alb', 'aws_subnet', 'aws_iam_instance_profile', 'aws_alb_listener', 'aws_launch_configuration', 'aws_internet_gateway', 'aws_alb_target_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: PR-AWS-TRF-ECS-012
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ECS-013
Title: VPC configurations on ECS Services must use either vended security groups\
Test Result: **passed**\
Description : ECS Service and ECS TaskSet resources set a SecurityGroup in the network_configuration. else Actor can exfiltrate data by associating ECS resources with non-ADATUM resources.\

#### Test Details
- eval: data.rule.ecs_security_group
- id : PR-AWS-TRF-ECS-013

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
| resourceTypes | ['aws_autoscaling_group', 'aws_security_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_route_table', 'aws_ecs_cluster', 'aws_route_table_association', 'aws_ecs_service', 'aws_ecs_task_definition', 'aws_iam_role', 'aws_cloudwatch_log_group', 'aws_alb', 'aws_subnet', 'aws_iam_instance_profile', 'aws_alb_listener', 'aws_launch_configuration', 'aws_internet_gateway', 'aws_alb_target_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: PR-AWS-TRF-ECS-013
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ECS-014
Title: Ensure that ECS Task Definition have their network mode property set to awsvpc\
Test Result: **failed**\
Description : Ensure that ECS Task Definition have their network mode property set to awsvpc. else an Actor can launch ECS service into an unsafe configuration allowing for external exposure or unaccounted for configurations\

#### Test Details
- eval: data.rule.ecs_network_mode
- id : PR-AWS-TRF-ECS-014

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
| resourceTypes | ['aws_autoscaling_group', 'aws_security_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_route_table', 'aws_ecs_cluster', 'aws_route_table_association', 'aws_ecs_service', 'aws_ecs_task_definition', 'aws_iam_role', 'aws_cloudwatch_log_group', 'aws_alb', 'aws_subnet', 'aws_iam_instance_profile', 'aws_alb_listener', 'aws_launch_configuration', 'aws_internet_gateway', 'aws_alb_target_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: PR-AWS-TRF-ECS-014
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are Janrypted and made available to the Lambda code.<br><br>This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-TRF-LMD-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT1                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_lambda_permission', 'aws_lambda_function', 'aws_iam_role', 'aws_iam_role_policy']                                                                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-001
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                              |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are Janrypted and made available to the Lambda code.<br><br>This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-TRF-LMD-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT6                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws_apigatewayv2_integration', 'aws_apigatewayv2_deployment', 'aws_apigatewayv2_stage', 'aws_apigatewayv2_route', 'aws_iam_role_policy_attachment', 'aws_lambda_permission', 'aws_iam_role', 'aws_iam_policy', 'aws_lambda_function', 'aws_apigatewayv2_api', 'aws_dynamodb_table']                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-001
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                              |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are Janrypted and made available to the Lambda code.<br><br>This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-TRF-LMD-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT9                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                          |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                               |
| resourceTypes | ['aws_iam_role', 'aws_lambda_function', 'aws_iam_role_policy', 'aws_cognito_user_pool']                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/cognito-user-pool/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/cognito-user-pool/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-001
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                              |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are Janrypted and made available to the Lambda code.<br><br>This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-TRF-LMD-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT21                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_iam_role', 'aws_lambda_function']                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-001
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                              |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-001
Title: AWS Lambda Environment Variables not encrypted at-rest using CMK\
Test Result: **failed**\
Description : When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are Janrypted and made available to the Lambda code.<br><br>This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.\

#### Test Details
- eval: data.rule.lambda_env
- id : PR-AWS-TRF-LMD-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT22                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws_default_vpc', 'aws_efs_file_system', 'aws_iam_role_policy_attachment', 'aws_iam_role', 'aws_efs_mount_target', 'aws_default_security_group', 'aws_lambda_function', 'aws_efs_access_point', 'aws_default_subnet']                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-001
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: High

tags
| Title      | Description                                                                |
|:-----------|:---------------------------------------------------------------------------|
| cloud      | git                                                                        |
| compliance | ['GDPR', 'CSA-CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                              |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-TRF-LMD-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT1                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_lambda_permission', 'aws_lambda_function', 'aws_iam_role', 'aws_iam_role_policy']                                                                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['PCI-DSS']   |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-TRF-LMD-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT6                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws_apigatewayv2_integration', 'aws_apigatewayv2_deployment', 'aws_apigatewayv2_stage', 'aws_apigatewayv2_route', 'aws_iam_role_policy_attachment', 'aws_lambda_permission', 'aws_iam_role', 'aws_iam_policy', 'aws_lambda_function', 'aws_apigatewayv2_api', 'aws_dynamodb_table']                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['PCI-DSS']   |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-TRF-LMD-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT9                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                          |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                               |
| resourceTypes | ['aws_iam_role', 'aws_lambda_function', 'aws_iam_role_policy', 'aws_cognito_user_pool']                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/cognito-user-pool/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/cognito-user-pool/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['PCI-DSS']   |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **failed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-TRF-LMD-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT21                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_iam_role', 'aws_lambda_function']                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['PCI-DSS']   |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-002
Title: AWS Lambda Function is not assigned to access within VPC\
Test Result: **passed**\
Description : This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).\

#### Test Details
- eval: data.rule.lambda_vpc
- id : PR-AWS-TRF-LMD-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT22                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws_default_vpc', 'aws_efs_file_system', 'aws_iam_role_policy_attachment', 'aws_iam_role', 'aws_efs_mount_target', 'aws_default_security_group', 'aws_lambda_function', 'aws_efs_access_point', 'aws_default_subnet']                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['PCI-DSS']   |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors.<br><br>The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing Janision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-TRF-LMD-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT1                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_lambda_permission', 'aws_lambda_function', 'aws_iam_role', 'aws_iam_role_policy']                                                                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['terraform']           |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors.<br><br>The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing Janision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-TRF-LMD-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT6                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws_apigatewayv2_integration', 'aws_apigatewayv2_deployment', 'aws_apigatewayv2_stage', 'aws_apigatewayv2_route', 'aws_iam_role_policy_attachment', 'aws_lambda_permission', 'aws_iam_role', 'aws_iam_policy', 'aws_lambda_function', 'aws_apigatewayv2_api', 'aws_dynamodb_table']                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['terraform']           |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors.<br><br>The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing Janision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-TRF-LMD-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT9                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                          |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                               |
| resourceTypes | ['aws_iam_role', 'aws_lambda_function', 'aws_iam_role_policy', 'aws_cognito_user_pool']                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/cognito-user-pool/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/cognito-user-pool/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['terraform']           |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors.<br><br>The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing Janision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-TRF-LMD-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT21                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_iam_role', 'aws_lambda_function']                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['terraform']           |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-003
Title: AWS Lambda functions with tracing not enabled\
Test Result: **failed**\
Description : TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors.<br><br>The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing Janision.\

#### Test Details
- eval: data.rule.lambda_tracing
- id : PR-AWS-TRF-LMD-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT22                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws_default_vpc', 'aws_efs_file_system', 'aws_iam_role_policy_attachment', 'aws_iam_role', 'aws_efs_mount_target', 'aws_default_security_group', 'aws_lambda_function', 'aws_efs_access_point', 'aws_default_subnet']                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Medium

tags
| Title      | Description             |
|:-----------|:------------------------|
| cloud      | git                     |
| compliance | ['HITRUST', 'NIST 800'] |
| service    | ['terraform']           |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-TRF-LMD-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT1                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_lambda_permission', 'aws_lambda_function', 'aws_iam_role', 'aws_iam_role_policy']                                                                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-004
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-TRF-LMD-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT6                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws_apigatewayv2_integration', 'aws_apigatewayv2_deployment', 'aws_apigatewayv2_stage', 'aws_apigatewayv2_route', 'aws_iam_role_policy_attachment', 'aws_lambda_permission', 'aws_iam_role', 'aws_iam_policy', 'aws_lambda_function', 'aws_apigatewayv2_api', 'aws_dynamodb_table']                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-004
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-TRF-LMD-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT9                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                          |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                               |
| resourceTypes | ['aws_iam_role', 'aws_lambda_function', 'aws_iam_role_policy', 'aws_cognito_user_pool']                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/cognito-user-pool/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/cognito-user-pool/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-004
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-TRF-LMD-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT21                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_iam_role', 'aws_lambda_function']                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-004
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-004
Title: Ensure AWS Lambda function is configured for function-level concurrent execution limit\
Test Result: **failed**\
Description : Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event\

#### Test Details
- eval: data.rule.lambda_concurrent_execution
- id : PR-AWS-TRF-LMD-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT22                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws_default_vpc', 'aws_efs_file_system', 'aws_iam_role_policy_attachment', 'aws_iam_role', 'aws_efs_mount_target', 'aws_default_security_group', 'aws_lambda_function', 'aws_efs_access_point', 'aws_default_subnet']                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-004
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **passed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-TRF-LMD-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT1                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['aws_lambda_permission', 'aws_lambda_function', 'aws_iam_role', 'aws_iam_role_policy']                                                                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-005
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **passed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-TRF-LMD-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT6                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws_apigatewayv2_integration', 'aws_apigatewayv2_deployment', 'aws_apigatewayv2_stage', 'aws_apigatewayv2_route', 'aws_iam_role_policy_attachment', 'aws_lambda_permission', 'aws_iam_role', 'aws_iam_policy', 'aws_lambda_function', 'aws_apigatewayv2_api', 'aws_dynamodb_table']                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-005
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **passed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-TRF-LMD-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT9                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                          |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                               |
| resourceTypes | ['aws_iam_role', 'aws_lambda_function', 'aws_iam_role_policy', 'aws_cognito_user_pool']                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/cognito-user-pool/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/cognito-user-pool/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-005
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **passed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-TRF-LMD-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT21                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['aws_iam_role', 'aws_lambda_function']                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-005
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-LMD-005
Title: Ensure AWS Lambda function is configured for a DLQ\
Test Result: **passed**\
Description : A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason\

#### Test Details
- eval: data.rule.lambda_dlq
- id : PR-AWS-TRF-LMD-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT22                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws_default_vpc', 'aws_efs_file_system', 'aws_iam_role_policy_attachment', 'aws_iam_role', 'aws_efs_mount_target', 'aws_default_security_group', 'aws_lambda_function', 'aws_efs_access_point', 'aws_default_subnet']                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/main.tf'] |

- masterTestId: PR-AWS-TRF-LMD-005
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/lambda.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------

