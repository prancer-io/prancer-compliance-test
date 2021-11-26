# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AWS (Nov 2021)

## Terraform Aws Networking Services 

Source Repository: https://github.com/hashicorp/terraform-provider-aws

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/

## Compliance run Meta Data
| Title     | Description         |
|:----------|:--------------------|
| timestamp | 1637184834855       |
| snapshot  | master-snapshot_gen |
| container | scenario-aws-terraform-hashicorp |
| test      | master-test.json    |

## Results

### Test ID - PR-AWS-TRF-AG-007
Title: AWS API Gateway endpoints without client certificate authentication\
Test Result: **failed**\
Description : API Gateway can generate an SSL certificate and use its public key in the backend to verify that HTTP requests to your backend system are from API Gateway. This allows your HTTP backend to control and accept only requests originating from Amazon API Gateway, even if the backend is publicly accessible._x005F_x000D_ _x005F_x000D_ Note: Some backend servers may not support SSL client authentication as API Gateway does and could return an SSL certificate error. For a list of incompatible backend servers, see Known Issues. https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html\

#### Test Details
- eval: data.rule.api_gw_cert
- id : PR-AWS-TRF-AG-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT3                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['aws_api_gateway_rest_api', 'aws_api_gateway_deployment']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/main.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/rest-api.tf'] |

- masterTestId: TEST_API_GATEWAY_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/api_gateway.rego)
- severity: Medium

tags
| Title      | Description                                     |
|:-----------|:------------------------------------------------|
| cloud      | git                                             |
| compliance | ['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800'] |
| service    | ['terraform']                                   |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-AG-007
Title: AWS API Gateway endpoints without client certificate authentication\
Test Result: **failed**\
Description : API Gateway can generate an SSL certificate and use its public key in the backend to verify that HTTP requests to your backend system are from API Gateway. This allows your HTTP backend to control and accept only requests originating from Amazon API Gateway, even if the backend is publicly accessible._x005F_x000D_ _x005F_x000D_ Note: Some backend servers may not support SSL client authentication as API Gateway does and could return an SSL certificate error. For a list of incompatible backend servers, see Known Issues. https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html\

#### Test Details
- eval: data.rule.api_gw_cert
- id : PR-AWS-TRF-AG-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT32                                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['aws_iam_policy', 'aws_api_gateway_method', 'aws_api_gateway_rest_api', 'aws_api_gateway_deployment', 'aws_iam_role_policy_attachment', 'aws_api_gateway_integration', 'aws_api_gateway_resource', 'aws_api_gateway_method_response', 'aws_api_gateway_integration_response', 'aws_iam_role']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/main.tf'] |

- masterTestId: TEST_API_GATEWAY_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/api_gateway.rego)
- severity: Medium

tags
| Title      | Description                                     |
|:-----------|:------------------------------------------------|
| cloud      | git                                             |
| compliance | ['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800'] |
| service    | ['terraform']                                   |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-AG-001
Title: API Gateway should have API Endpoint type as private and not exposed to internet\
Test Result: **failed**\
Description : Ensure that the Api endpoint type in api gateway is set to private and Is not exposed to the public internet\

#### Test Details
- eval: data.rule.gateway_private
- id : PR-AWS-TRF-AG-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT3                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['aws_api_gateway_rest_api', 'aws_api_gateway_deployment']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/main.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/rest-api.tf'] |

- masterTestId: TEST_API_GATEWAY_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/api_gateway.rego)
- severity: High

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-AG-001
Title: API Gateway should have API Endpoint type as private and not exposed to internet\
Test Result: **passed**\
Description : Ensure that the Api endpoint type in api gateway is set to private and Is not exposed to the public internet\

#### Test Details
- eval: data.rule.gateway_private
- id : PR-AWS-TRF-AG-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT32                                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['aws_iam_policy', 'aws_api_gateway_method', 'aws_api_gateway_rest_api', 'aws_api_gateway_deployment', 'aws_iam_role_policy_attachment', 'aws_api_gateway_integration', 'aws_api_gateway_resource', 'aws_api_gateway_method_response', 'aws_api_gateway_integration_response', 'aws_iam_role']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/main.tf'] |

- masterTestId: TEST_API_GATEWAY_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/api_gateway.rego)
- severity: High

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-AG-004
Title: Ensure that API Gateway has enabled access logging\
Test Result: **passed**\
Description : Enabling the custom access logging option in API Gateway allows delivery of custom logs to CloudWatch Logs, which can be analyzed using CloudWatch Logs Insights. Using custom domain names in Amazon API Gateway allows insights into requests sent to each custom domain name.\

#### Test Details
- eval: data.rule.gateway_logging_enable
- id : PR-AWS-TRF-AG-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT4                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws_api_gateway_stage', 'aws_api_gateway_method_settings']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/main.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/stage.tf'] |

- masterTestId: TEST_API_GATEWAY_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/api_gateway.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-AG-005
Title: Ensure API Gateway has tracing enabled\
Test Result: **failed**\
Description : With tracing enabled X-Ray can provide an end-to-end view of an entire HTTP request. You can use this to analyze latencies in APIs and their backend services\

#### Test Details
- eval: data.rule.gateway_tracing_enable
- id : PR-AWS-TRF-AG-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT4                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['aws_api_gateway_stage', 'aws_api_gateway_method_settings']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/main.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/stage.tf'] |

- masterTestId: TEST_API_GATEWAY_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/api_gateway.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-AG-006
Title: Ensure API gateway methods are not publicly accessible\
Test Result: **passed**\
Description : We recommend you configure a custom authorizer OR an API key for every method in the API Gateway.\

#### Test Details
- eval: data.rule.gateway_method_public_access
- id : PR-AWS-TRF-AG-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT32                                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['aws_iam_policy', 'aws_api_gateway_method', 'aws_api_gateway_rest_api', 'aws_api_gateway_deployment', 'aws_iam_role_policy_attachment', 'aws_api_gateway_integration', 'aws_api_gateway_resource', 'aws_api_gateway_method_response', 'aws_api_gateway_integration_response', 'aws_iam_role']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/main.tf'] |

- masterTestId: TEST_API_GATEWAY_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/api_gateway.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-TRF-VPC-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT8                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['aws_cloudhsm_v2_hsm', 'aws_subnet', 'aws_cloudhsm_v2_cluster', 'aws_vpc']                                                                                                                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/cloudhsm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/cloudhsm/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/cloudhsm/main.tf'] |

- masterTestId: TEST_VPC_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-TRF-VPC-001

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
| resourceTypes | ['aws_security_group', 'aws_internet_gateway', 'aws_alb_listener', 'aws_ecs_service', 'aws_alb_target_group', 'aws_alb', 'aws_autoscaling_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_iam_instance_profile', 'aws_route_table', 'aws_subnet', 'aws_launch_configuration', 'aws_ecs_task_definition', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_ecs_cluster', 'aws_iam_role'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_VPC_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **failed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-TRF-VPC-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT16                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_route_table_association']                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/vpc.tf'] |

- masterTestId: TEST_VPC_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **failed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-TRF-VPC-001

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
| resourceTypes | ['aws_elb', 'aws_instance', 'aws_security_group', 'aws_internet_gateway', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_route_table_association']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: TEST_VPC_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-TRF-VPC-001

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
| resourceTypes | ['aws_route_table_association', 'aws_route_table', 'aws_security_group', 'aws_subnet']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/subnets.tf'] |

- masterTestId: TEST_VPC_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-TRF-VPC-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT27                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['aws_route_table_association', 'aws_route_table', 'aws_subnet']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/subnet/subnet.tf'] |

- masterTestId: TEST_VPC_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-TRF-VPC-001

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
| resourceTypes | ['aws_security_group', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_route_table_association']                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/regions.tf'] |

- masterTestId: TEST_VPC_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-TRF-VPC-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT31                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_subnet']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnets.tf'] |

- masterTestId: TEST_VPC_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-TRF-VPC-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT36                                                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['aws_ec2_transit_gateway', 'aws_vpc', 'aws_ram_resource_association', 'aws_ec2_transit_gateway_vpc_attachment', 'aws_ram_resource_share', 'aws_ram_principal_association', 'aws_subnet', 'aws_ec2_transit_gateway_vpc_attachment_accepter']                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/transit-gateway-cross-account-vpc-attachment/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/transit-gateway-cross-account-vpc-attachment/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/transit-gateway-cross-account-vpc-attachment/main.tf'] |

- masterTestId: TEST_VPC_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **failed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-TRF-VPC-001

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
| resourceTypes | ['aws_elb', 'aws_instance', 'aws_security_group', 'aws_internet_gateway', 'aws_key_pair', 'aws_vpc', 'aws_route', 'aws_subnet']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_VPC_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-VPC-001
Title: AWS VPC subnets should not allow automatic public IP assignment\
Test Result: **passed**\
Description : This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.\

#### Test Details
- eval: data.rule.vpc_subnet_autoip
- id : PR-AWS-TRF-VPC-001

#### Snapshots
| Title         | Description                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT38                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                            |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                 |
| resourceTypes | ['aws_directory_service_directory', 'aws_vpc', 'aws_workspaces_directory', 'aws_subnet', 'aws_kms_key', 'aws_workspaces_workspace', 'aws_workspaces_ip_group']                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/workspaces/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/workspaces/main.tf'] |

- masterTestId: TEST_VPC_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/vpc.rego)
- severity: Medium

tags
| Title      | Description                                                         |
|:-----------|:--------------------------------------------------------------------|
| cloud      | git                                                                 |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF'] |
| service    | ['terraform']                                                       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-VPC-002
Title: Ensure all EIP addresses allocated to a VPC are attached related EC2 instances\
Test Result: **passed**\
Description : Ensure that a managed Config rule for AWS Elastic IPs (EIPs) attached to EC2 instances launched inside a VPC is created. Config service tracks changes within your AWS resources configuration and saves the recorded data for security and compliance audits\

#### Test Details
- eval: data.rule.eip_instance_link
- id : PR-AWS-TRF-VPC-002

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
| resourceTypes | ['aws_instance', 'aws_security_group', 'aws_eip']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_VPC_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/vpc.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-TRF-SG-030

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
| resourceTypes | ['aws_security_group', 'aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group']                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_30
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


### Test ID - PR-AWS-TRF-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-TRF-SG-030

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
| resourceTypes | ['aws_security_group', 'aws_internet_gateway', 'aws_alb_listener', 'aws_ecs_service', 'aws_alb_target_group', 'aws_alb', 'aws_autoscaling_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_iam_instance_profile', 'aws_route_table', 'aws_subnet', 'aws_launch_configuration', 'aws_ecs_task_definition', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_ecs_cluster', 'aws_iam_role'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_SECURITY_GROUP_30
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


### Test ID - PR-AWS-TRF-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-TRF-SG-030

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
| resourceTypes | ['aws_instance', 'aws_security_group', 'aws_eip']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_30
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


### Test ID - PR-AWS-TRF-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-TRF-SG-030

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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_30
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


### Test ID - PR-AWS-TRF-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-TRF-SG-030

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
| resourceTypes | ['aws_elb', 'aws_instance', 'aws_security_group', 'aws_internet_gateway', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_route_table_association']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_30
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


### Test ID - PR-AWS-TRF-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-TRF-SG-030

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

- masterTestId: TEST_SECURITY_GROUP_30
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


### Test ID - PR-AWS-TRF-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-TRF-SG-030

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
| resourceTypes | ['aws_route_table_association', 'aws_route_table', 'aws_security_group', 'aws_subnet']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/subnets.tf'] |

- masterTestId: TEST_SECURITY_GROUP_30
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


### Test ID - PR-AWS-TRF-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-TRF-SG-030

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

- masterTestId: TEST_SECURITY_GROUP_30
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


### Test ID - PR-AWS-TRF-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-TRF-SG-030

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
| resourceTypes | ['aws_security_group', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_route_table_association']                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/regions.tf'] |

- masterTestId: TEST_SECURITY_GROUP_30
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


### Test ID - PR-AWS-TRF-SG-030
Title: Publicly exposed DB Ports\
Test Result: **failed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-TRF-SG-030

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

- masterTestId: TEST_SECURITY_GROUP_30
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


### Test ID - PR-AWS-TRF-SG-030
Title: Publicly exposed DB Ports\
Test Result: **passed**\
Description : DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).\

#### Test Details
- eval: data.rule.db_exposed
- id : PR-AWS-TRF-SG-030

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
| resourceTypes | ['aws_elb', 'aws_instance', 'aws_security_group', 'aws_internet_gateway', 'aws_key_pair', 'aws_vpc', 'aws_route', 'aws_subnet']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_30
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


### Test ID - PR-AWS-TRF-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-TRF-SG-031

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
| resourceTypes | ['aws_security_group', 'aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group']                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_31
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-TRF-SG-031

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
| resourceTypes | ['aws_security_group', 'aws_internet_gateway', 'aws_alb_listener', 'aws_ecs_service', 'aws_alb_target_group', 'aws_alb', 'aws_autoscaling_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_iam_instance_profile', 'aws_route_table', 'aws_subnet', 'aws_launch_configuration', 'aws_ecs_task_definition', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_ecs_cluster', 'aws_iam_role'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_SECURITY_GROUP_31
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-TRF-SG-031

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
| resourceTypes | ['aws_instance', 'aws_security_group', 'aws_eip']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_31
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-TRF-SG-031

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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_31
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-TRF-SG-031

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
| resourceTypes | ['aws_elb', 'aws_instance', 'aws_security_group', 'aws_internet_gateway', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_route_table_association']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_31
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-TRF-SG-031

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

- masterTestId: TEST_SECURITY_GROUP_31
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-TRF-SG-031

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
| resourceTypes | ['aws_route_table_association', 'aws_route_table', 'aws_security_group', 'aws_subnet']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/subnets.tf'] |

- masterTestId: TEST_SECURITY_GROUP_31
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-TRF-SG-031

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

- masterTestId: TEST_SECURITY_GROUP_31
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-TRF-SG-031

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
| resourceTypes | ['aws_security_group', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_route_table_association']                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/regions.tf'] |

- masterTestId: TEST_SECURITY_GROUP_31
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **failed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-TRF-SG-031

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

- masterTestId: TEST_SECURITY_GROUP_31
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-031
Title: Instance is communicating with ports known to mine Bitcoin\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.bitcoin_ports
- id : PR-AWS-TRF-SG-031

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
| resourceTypes | ['aws_elb', 'aws_instance', 'aws_security_group', 'aws_internet_gateway', 'aws_key_pair', 'aws_vpc', 'aws_route', 'aws_subnet']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_31
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-TRF-SG-032

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
| resourceTypes | ['aws_security_group', 'aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group']                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/asg/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_32
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-TRF-SG-032

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
| resourceTypes | ['aws_security_group', 'aws_internet_gateway', 'aws_alb_listener', 'aws_ecs_service', 'aws_alb_target_group', 'aws_alb', 'aws_autoscaling_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_iam_instance_profile', 'aws_route_table', 'aws_subnet', 'aws_launch_configuration', 'aws_ecs_task_definition', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_ecs_cluster', 'aws_iam_role'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: TEST_SECURITY_GROUP_32
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-TRF-SG-032

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
| resourceTypes | ['aws_instance', 'aws_security_group', 'aws_eip']                                                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eip/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_32
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-TRF-SG-032

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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_32
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-TRF-SG-032

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
| resourceTypes | ['aws_elb', 'aws_instance', 'aws_security_group', 'aws_internet_gateway', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_route_table_association']                                                                                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/elb/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_32
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-TRF-SG-032

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

- masterTestId: TEST_SECURITY_GROUP_32
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-TRF-SG-032

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
| resourceTypes | ['aws_route_table_association', 'aws_route_table', 'aws_security_group', 'aws_subnet']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/region/subnets.tf'] |

- masterTestId: TEST_SECURITY_GROUP_32
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-TRF-SG-032

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

- masterTestId: TEST_SECURITY_GROUP_32
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-TRF-SG-032

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
| resourceTypes | ['aws_security_group', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_route_table_association']                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/versions.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/networking/regions.tf'] |

- masterTestId: TEST_SECURITY_GROUP_32
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **failed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-TRF-SG-032

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

- masterTestId: TEST_SECURITY_GROUP_32
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-032
Title: Instance is communicating with ports known to mine Ethereum\
Test Result: **passed**\
Description : Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.\

#### Test Details
- eval: data.rule.ethereum_ports
- id : PR-AWS-TRF-SG-032

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
| resourceTypes | ['aws_elb', 'aws_instance', 'aws_security_group', 'aws_internet_gateway', 'aws_key_pair', 'aws_vpc', 'aws_route', 'aws_subnet']                                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/two-tier/main.tf'] |

- masterTestId: TEST_SECURITY_GROUP_32
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego)
- severity: Medium

tags
| Title      | Description           |
|:-----------|:----------------------|
| cloud      | git                   |
| compliance | ['HIPAA', 'NIST 800'] |
| service    | ['terraform']         |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-TRF-SG-001

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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_1
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


### Test ID - PR-AWS-TRF-SG-001
Title: AWS Security Groups allow internet traffic from internet to Windows RPC port (135)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_135
- id : PR-AWS-TRF-SG-001

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

- masterTestId: TEST_SECURITY_GROUP_1
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


### Test ID - PR-AWS-TRF-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-TRF-SG-002

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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_2
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


### Test ID - PR-AWS-TRF-SG-002
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (137)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_137
- id : PR-AWS-TRF-SG-002

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

- masterTestId: TEST_SECURITY_GROUP_2
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


### Test ID - PR-AWS-TRF-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-TRF-SG-003

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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_3
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


### Test ID - PR-AWS-TRF-SG-003
Title: AWS Security Groups allow internet traffic from internet to NetBIOS port (138)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_138
- id : PR-AWS-TRF-SG-003

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

- masterTestId: TEST_SECURITY_GROUP_3
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


### Test ID - PR-AWS-TRF-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-TRF-SG-004

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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_4
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


### Test ID - PR-AWS-TRF-SG-004
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1433)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1433
- id : PR-AWS-TRF-SG-004

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

- masterTestId: TEST_SECURITY_GROUP_4
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


### Test ID - PR-AWS-TRF-SG-005
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1434)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1434) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1434) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1434
- id : PR-AWS-TRF-SG-005

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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_5
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


### Test ID - PR-AWS-TRF-SG-005
Title: AWS Security Groups allow internet traffic from internet to SQLServer port (1434)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing SQLServer port (1434) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1434) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_1434
- id : PR-AWS-TRF-SG-005

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

- masterTestId: TEST_SECURITY_GROUP_5
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


### Test ID - PR-AWS-TRF-SG-006
Title: AWS Security Groups allow internet traffic from internet to FTP-Data port (20)\
Test Result: **passed**\
Description : This policy identifies the security groups which are exposing FTP-Data port (20) to the internet. It is recommended that Global permission to access the well known services FTP-Data port (20) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_20
- id : PR-AWS-TRF-SG-006

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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: TEST_SECURITY_GROUP_6
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


### Test ID - PR-AWS-TRF-SG-006
Title: AWS Security Groups allow internet traffic from internet to FTP-Data port (20)\
Test Result: **failed**\
Description : This policy identifies the security groups which are exposing FTP-Data port (20) to the internet. It is recommended that Global permission to access the well known services FTP-Data port (20) should not be allowed in a security group.\

#### Test Details
- eval: data.rule.port_20
- id : PR-AWS-TRF-SG-006

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

- masterTestId: TEST_SECURITY_GROUP_6
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT14                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

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
| resourceTypes | ['aws_security_group', 'aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group']                                                                                                                                                                                                                                                                                             |
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
| resourceTypes | ['aws_instance', 'aws_security_group', 'aws_eip']                                                                                                                                                                                                                                                                                                                                  |
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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_elb', 'aws_instance', 'aws_security_group', 'aws_internet_gateway', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_route_table_association']                                                                                                                                                                                            |
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
| resourceTypes | ['aws_elb', 'aws_instance', 'aws_security_group', 'aws_internet_gateway', 'aws_key_pair', 'aws_vpc', 'aws_route', 'aws_subnet']                                                                                                                                                                                                                                                                        |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT14                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_security_group', 'aws_elb', 'aws_launch_configuration', 'aws_autoscaling_group']                                                                                                                                                                                                                                                                                             |
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
| resourceTypes | ['aws_security_group', 'aws_internet_gateway', 'aws_alb_listener', 'aws_ecs_service', 'aws_alb_target_group', 'aws_alb', 'aws_autoscaling_group', 'aws_vpc', 'aws_iam_role_policy', 'aws_iam_instance_profile', 'aws_route_table', 'aws_subnet', 'aws_launch_configuration', 'aws_ecs_task_definition', 'aws_cloudwatch_log_group', 'aws_route_table_association', 'aws_ecs_cluster', 'aws_iam_role'] |
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
| resourceTypes | ['aws_instance', 'aws_security_group', 'aws_eip']                                                                                                                                                                                                                                                                                                                                  |
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
| resourceTypes | ['aws_eks_cluster', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment', 'aws_iam_role']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_elb', 'aws_instance', 'aws_security_group', 'aws_internet_gateway', 'aws_lb_cookie_stickiness_policy', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_route_table_association']                                                                                                                                                                                            |
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
| resourceTypes | ['aws_route_table_association', 'aws_route_table', 'aws_security_group', 'aws_subnet']                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
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
| resourceTypes | ['aws_security_group', 'aws_internet_gateway', 'aws_vpc', 'aws_route_table', 'aws_subnet', 'aws_route_table_association']                                                                                                                                                                           |
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
| resourceTypes | ['aws_elb', 'aws_instance', 'aws_security_group', 'aws_internet_gateway', 'aws_key_pair', 'aws_vpc', 'aws_route', 'aws_subnet']                                                                                                                                                                                                                                                                        |
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

