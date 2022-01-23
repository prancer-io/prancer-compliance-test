# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AWS (Jan 2022)

## All Services

#### Compute: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Compute.md
#### Data Store: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20DataStore.md
#### Management: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Management.md
#### Networking (Part1): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Networking%20(Part1).md
#### Networking (Part2): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Networking%20(Part2).md
#### Networking (Part3): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Networking%20(Part3).md
#### Security: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/aws/Jan-2022/output23012022%20Aws%20Security.md

## Terraform Aws Security Services

Source Repository: https://github.com/hashicorp/terraform-provider-aws

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform

## Compliance run Meta Data
| Title     | Description                      |
|:----------|:---------------------------------|
| timestamp | 1642964146535                    |
| snapshot  | master-snapshot_gen              |
| container | scenario-aws-terraform-hashicorp |
| test      | master-test.json                 |

## Results

### Test ID - PR-AWS-TRF-KMS-001
Title: AWS Customer Master Key (CMK) rotation is not enabled\
Test Result: **failed**\
Description : This policy identifies Customer Master Keys (CMKs) that are not enabled with key rotation. AWS KMS (Key Management Service) allows customers to create master keys to encrypt sensitive data in different services. As a security best practice, it is important to rotate the keys periodically so that if the keys are compromised, the data in the underlying service is still secure with the new keys.\

#### Test Details
- eval: data.rule.kms_key_rotation
- id : PR-AWS-TRF-KMS-001

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
| resourceTypes | ['aws_workspaces_workspace', 'aws_kms_key', 'aws_workspaces_directory', 'aws_vpc', 'aws_subnet', 'aws_directory_service_directory', 'aws_workspaces_ip_group']                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/workspaces/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/workspaces/main.tf'] |

- masterTestId: PR-AWS-TRF-KMS-001
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/kms.rego)
- severity: Medium

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['NIST 800', 'CIS'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-KMS-002
Title: AWS KMS Customer Managed Key not in use\
Test Result: **failed**\
Description : This policy identifies KMS Customer Managed Keys(CMKs) which are not usable. When you create a CMK, it is enabled by default. If you disable a CMK or schedule it for deletion makes it unusable, it cannot be used to encrypt or decrypt data and AWS KMS does not rotate the backing keys until you re-enable it.\

#### Test Details
- eval: data.rule.kms_key_state
- id : PR-AWS-TRF-KMS-002

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
| resourceTypes | ['aws_workspaces_workspace', 'aws_kms_key', 'aws_workspaces_directory', 'aws_vpc', 'aws_subnet', 'aws_directory_service_directory', 'aws_workspaces_ip_group']                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/workspaces/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/workspaces/main.tf'] |

- masterTestId: PR-AWS-TRF-KMS-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/kms.rego)
- severity: Medium

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-KMS-003
Title: Ensure no KMS key policy contain wildcard (*) principal\
Test Result: **passed**\
Description : This policy revents all user access to specific resource/s and actions\

#### Test Details
- eval: data.rule.kms_key_allow_all_principal
- id : PR-AWS-TRF-KMS-003

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
| resourceTypes | ['aws_workspaces_workspace', 'aws_kms_key', 'aws_workspaces_directory', 'aws_vpc', 'aws_subnet', 'aws_directory_service_directory', 'aws_workspaces_ip_group']                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/workspaces/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/workspaces/main.tf'] |

- masterTestId: PR-AWS-TRF-KMS-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/kms.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-001
Title: Ensure no wildcards are specified in IAM policy with 'Resource' section\
Test Result: **passed**\
Description : Using a wildcard in the Resource element in a role's trust policy would allow any IAM user in an account to access all resources. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_resource
- id : PR-AWS-TRF-IAM-001

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
| resourceTypes | ['aws_apigatewayv2_deployment', 'aws_iam_role', 'aws_apigatewayv2_route', 'aws_dynamodb_table', 'aws_apigatewayv2_integration', 'aws_lambda_function', 'aws_apigatewayv2_stage', 'aws_lambda_permission', 'aws_iam_policy', 'aws_apigatewayv2_api', 'aws_iam_role_policy_attachment']                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-001
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-001
Title: Ensure no wildcards are specified in IAM policy with 'Resource' section\
Test Result: **failed**\
Description : Using a wildcard in the Resource element in a role's trust policy would allow any IAM user in an account to access all resources. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_resource
- id : PR-AWS-TRF-IAM-001

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
| resourceTypes | ['aws_api_gateway_rest_api', 'aws_iam_role', 'aws_api_gateway_resource', 'aws_api_gateway_deployment', 'aws_api_gateway_integration', 'aws_api_gateway_integration_response', 'aws_iam_policy', 'aws_iam_role_policy_attachment', 'aws_api_gateway_method_response', 'aws_api_gateway_method']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-001
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-001
Title: Ensure no wildcards are specified in IAM policy with 'Resource' section\
Test Result: **passed**\
Description : Using a wildcard in the Resource element in a role's trust policy would allow any IAM user in an account to access all resources. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_resource
- id : PR-AWS-TRF-IAM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT34                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                     |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                          |
| resourceTypes | ['aws_sagemaker_endpoint', 'aws_iam_role', 'aws_s3_bucket', 'aws_sagemaker_model', 'aws_sagemaker_endpoint_configuration', 'aws_s3_bucket_object', 'aws_iam_policy', 'random_integer', 'aws_iam_role_policy_attachment'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: PR-AWS-TRF-IAM-001
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-002
Title: Ensure no wildcards are specified in IAM policy with 'Action' section\
Test Result: **passed**\
Description : Using a wildcard in the Action element in a role's trust policy would allow any IAM user in an account to Manage all resources and a user can manipulate data. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_action
- id : PR-AWS-TRF-IAM-002

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
| resourceTypes | ['aws_apigatewayv2_deployment', 'aws_iam_role', 'aws_apigatewayv2_route', 'aws_dynamodb_table', 'aws_apigatewayv2_integration', 'aws_lambda_function', 'aws_apigatewayv2_stage', 'aws_lambda_permission', 'aws_iam_policy', 'aws_apigatewayv2_api', 'aws_iam_role_policy_attachment']                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-002
Title: Ensure no wildcards are specified in IAM policy with 'Action' section\
Test Result: **passed**\
Description : Using a wildcard in the Action element in a role's trust policy would allow any IAM user in an account to Manage all resources and a user can manipulate data. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_action
- id : PR-AWS-TRF-IAM-002

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
| resourceTypes | ['aws_api_gateway_rest_api', 'aws_iam_role', 'aws_api_gateway_resource', 'aws_api_gateway_deployment', 'aws_api_gateway_integration', 'aws_api_gateway_integration_response', 'aws_iam_policy', 'aws_iam_role_policy_attachment', 'aws_api_gateway_method_response', 'aws_api_gateway_method']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-002
Title: Ensure no wildcards are specified in IAM policy with 'Action' section\
Test Result: **passed**\
Description : Using a wildcard in the Action element in a role's trust policy would allow any IAM user in an account to Manage all resources and a user can manipulate data. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_action
- id : PR-AWS-TRF-IAM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT34                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                     |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                          |
| resourceTypes | ['aws_sagemaker_endpoint', 'aws_iam_role', 'aws_s3_bucket', 'aws_sagemaker_model', 'aws_sagemaker_endpoint_configuration', 'aws_s3_bucket_object', 'aws_iam_policy', 'random_integer', 'aws_iam_role_policy_attachment'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: PR-AWS-TRF-IAM-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-TRF-IAM-003

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
| resourceTypes | ['aws_lambda_permission', 'aws_lambda_function', 'aws_iam_role_policy', 'aws_iam_role']                                                                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/alexa/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-TRF-IAM-003

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
| resourceTypes | ['aws_apigatewayv2_deployment', 'aws_iam_role', 'aws_apigatewayv2_route', 'aws_dynamodb_table', 'aws_apigatewayv2_integration', 'aws_lambda_function', 'aws_apigatewayv2_stage', 'aws_lambda_permission', 'aws_iam_policy', 'aws_apigatewayv2_api', 'aws_iam_role_policy_attachment']                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-TRF-IAM-003

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
| resourceTypes | ['aws_lambda_function', 'aws_iam_role_policy', 'aws_cognito_user_pool', 'aws_iam_role']                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/cognito-user-pool/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/cognito-user-pool/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-TRF-IAM-003

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
| resourceTypes | ['aws_alb', 'aws_autoscaling_group', 'aws_alb_target_group', 'aws_route_table', 'aws_ecs_cluster', 'aws_ecs_service', 'aws_iam_role', 'aws_iam_role_policy', 'aws_route_table_association', 'aws_alb_listener', 'aws_vpc', 'aws_subnet', 'aws_internet_gateway', 'aws_security_group', 'aws_ecs_task_definition', 'aws_cloudwatch_log_group', 'aws_iam_instance_profile', 'aws_launch_configuration'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/ecs-alb/main.tf']    |

- masterTestId: PR-AWS-TRF-IAM-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-TRF-IAM-003

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
| resourceTypes | ['aws_eks_cluster', 'aws_iam_role', 'aws_security_group_rule', 'aws_security_group', 'aws_iam_role_policy_attachment']                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-cluster.tf'] |

- masterTestId: PR-AWS-TRF-IAM-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-TRF-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT15                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['aws_iam_role', 'aws_eks_node_group', 'aws_iam_role_policy_attachment']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/providers.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/workstation-external-ip.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/eks-getting-started/eks-worker-nodes.tf'] |

- masterTestId: PR-AWS-TRF-IAM-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-TRF-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT19                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['aws_iam_role', 'aws_cloudwatch_event_rule', 'aws_iam_role_policy', 'aws_cloudwatch_event_target', 'aws_kinesis_stream']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/events/kinesis/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/events/kinesis/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/events/kinesis/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-TRF-IAM-003

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
| resourceTypes | ['aws_lambda_function', 'aws_iam_role']                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-TRF-IAM-003

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
| resourceTypes | ['aws_default_subnet', 'aws_efs_mount_target', 'aws_iam_role', 'aws_efs_file_system', 'aws_lambda_function', 'aws_default_vpc', 'aws_default_security_group', 'aws_efs_access_point', 'aws_iam_role_policy_attachment']                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-TRF-IAM-003

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
| resourceTypes | ['aws_api_gateway_rest_api', 'aws_iam_role', 'aws_api_gateway_resource', 'aws_api_gateway_deployment', 'aws_api_gateway_integration', 'aws_api_gateway_integration_response', 'aws_iam_policy', 'aws_iam_role_policy_attachment', 'aws_api_gateway_method_response', 'aws_api_gateway_method']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-003
Title: Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section\
Test Result: **passed**\
Description : Using a wildcard in the Principal element in a role's trust policy would allow any IAM user in any account to access the role. This is a significant security gap and can be used to gain access to sensitive data.\

#### Test Details
- eval: data.rule.iam_wildcard_principal
- id : PR-AWS-TRF-IAM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT34                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                     |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                          |
| resourceTypes | ['aws_sagemaker_endpoint', 'aws_iam_role', 'aws_s3_bucket', 'aws_sagemaker_model', 'aws_sagemaker_endpoint_configuration', 'aws_s3_bucket_object', 'aws_iam_policy', 'random_integer', 'aws_iam_role_policy_attachment'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: PR-AWS-TRF-IAM-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['CIS', 'NIST 800'] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-005
Title: AWS IAM policy allows assume role permission across all services\
Test Result: **passed**\
Description : This policy identifies AWS IAM policy which allows assume role permission across all services. Typically, AssumeRole is used if you have multiple accounts and need to access resources from each account then you can create long term credentials in one account and then use temporary security credentials to access all the other accounts by assuming roles in those accounts.\

#### Test Details
- eval: data.rule.iam_assume_permission
- id : PR-AWS-TRF-IAM-005

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
| resourceTypes | ['aws_apigatewayv2_deployment', 'aws_iam_role', 'aws_apigatewayv2_route', 'aws_dynamodb_table', 'aws_apigatewayv2_integration', 'aws_lambda_function', 'aws_apigatewayv2_stage', 'aws_lambda_permission', 'aws_iam_policy', 'aws_apigatewayv2_api', 'aws_iam_role_policy_attachment']                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-005
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description                                                                       |
|:-----------|:----------------------------------------------------------------------------------|
| cloud      | git                                                                               |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2'] |
| service    | ['terraform']                                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-005
Title: AWS IAM policy allows assume role permission across all services\
Test Result: **passed**\
Description : This policy identifies AWS IAM policy which allows assume role permission across all services. Typically, AssumeRole is used if you have multiple accounts and need to access resources from each account then you can create long term credentials in one account and then use temporary security credentials to access all the other accounts by assuming roles in those accounts.\

#### Test Details
- eval: data.rule.iam_assume_permission
- id : PR-AWS-TRF-IAM-005

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
| resourceTypes | ['aws_api_gateway_rest_api', 'aws_iam_role', 'aws_api_gateway_resource', 'aws_api_gateway_deployment', 'aws_api_gateway_integration', 'aws_api_gateway_integration_response', 'aws_iam_policy', 'aws_iam_role_policy_attachment', 'aws_api_gateway_method_response', 'aws_api_gateway_method']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-005
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description                                                                       |
|:-----------|:----------------------------------------------------------------------------------|
| cloud      | git                                                                               |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2'] |
| service    | ['terraform']                                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-005
Title: AWS IAM policy allows assume role permission across all services\
Test Result: **passed**\
Description : This policy identifies AWS IAM policy which allows assume role permission across all services. Typically, AssumeRole is used if you have multiple accounts and need to access resources from each account then you can create long term credentials in one account and then use temporary security credentials to access all the other accounts by assuming roles in those accounts.\

#### Test Details
- eval: data.rule.iam_assume_permission
- id : PR-AWS-TRF-IAM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT34                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                     |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                          |
| resourceTypes | ['aws_sagemaker_endpoint', 'aws_iam_role', 'aws_s3_bucket', 'aws_sagemaker_model', 'aws_sagemaker_endpoint_configuration', 'aws_s3_bucket_object', 'aws_iam_policy', 'random_integer', 'aws_iam_role_policy_attachment'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: PR-AWS-TRF-IAM-005
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: High

tags
| Title      | Description                                                                       |
|:-----------|:----------------------------------------------------------------------------------|
| cloud      | git                                                                               |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2'] |
| service    | ['terraform']                                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-006
Title: AWS IAM policy is overly permissive to all traffic via condition clause\
Test Result: **passed**\
Description : This policy identifies IAM policies that have a policy that is overly permissive to all traffic via condition clause. If any IAM policy statement with a condition containing 0.0.0.0/0 or ::/0, it allows all traffic to resources attached to that IAM policy. It is highly recommended to have the least privileged IAM policy to protect the data leakage and unauthorized access.\

#### Test Details
- eval: data.rule.iam_all_traffic
- id : PR-AWS-TRF-IAM-006

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
| resourceTypes | ['aws_apigatewayv2_deployment', 'aws_iam_role', 'aws_apigatewayv2_route', 'aws_dynamodb_table', 'aws_apigatewayv2_integration', 'aws_lambda_function', 'aws_apigatewayv2_stage', 'aws_lambda_permission', 'aws_iam_policy', 'aws_apigatewayv2_api', 'aws_iam_role_policy_attachment']                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-006
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['CIS']       |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-006
Title: AWS IAM policy is overly permissive to all traffic via condition clause\
Test Result: **passed**\
Description : This policy identifies IAM policies that have a policy that is overly permissive to all traffic via condition clause. If any IAM policy statement with a condition containing 0.0.0.0/0 or ::/0, it allows all traffic to resources attached to that IAM policy. It is highly recommended to have the least privileged IAM policy to protect the data leakage and unauthorized access.\

#### Test Details
- eval: data.rule.iam_all_traffic
- id : PR-AWS-TRF-IAM-006

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
| resourceTypes | ['aws_api_gateway_rest_api', 'aws_iam_role', 'aws_api_gateway_resource', 'aws_api_gateway_deployment', 'aws_api_gateway_integration', 'aws_api_gateway_integration_response', 'aws_iam_policy', 'aws_iam_role_policy_attachment', 'aws_api_gateway_method_response', 'aws_api_gateway_method']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-006
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['CIS']       |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-006
Title: AWS IAM policy is overly permissive to all traffic via condition clause\
Test Result: **passed**\
Description : This policy identifies IAM policies that have a policy that is overly permissive to all traffic via condition clause. If any IAM policy statement with a condition containing 0.0.0.0/0 or ::/0, it allows all traffic to resources attached to that IAM policy. It is highly recommended to have the least privileged IAM policy to protect the data leakage and unauthorized access.\

#### Test Details
- eval: data.rule.iam_all_traffic
- id : PR-AWS-TRF-IAM-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT34                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                     |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                          |
| resourceTypes | ['aws_sagemaker_endpoint', 'aws_iam_role', 'aws_s3_bucket', 'aws_sagemaker_model', 'aws_sagemaker_endpoint_configuration', 'aws_s3_bucket_object', 'aws_iam_policy', 'random_integer', 'aws_iam_role_policy_attachment'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: PR-AWS-TRF-IAM-006
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['CIS']       |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-007
Title: AWS IAM policy allows full administrative privileges\
Test Result: **passed**\
Description : This policy identifies IAM policies with full administrative privileges. IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege like granting only the permissions required to perform a task. Determine what users need to do and then craft policies for them that let the users perform only those tasks, instead of allowing full administrative privileges.\

#### Test Details
- eval: data.rule.iam_administrative_privileges
- id : PR-AWS-TRF-IAM-007

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
| resourceTypes | ['aws_apigatewayv2_deployment', 'aws_iam_role', 'aws_apigatewayv2_route', 'aws_dynamodb_table', 'aws_apigatewayv2_integration', 'aws_lambda_function', 'aws_apigatewayv2_stage', 'aws_lambda_permission', 'aws_iam_policy', 'aws_apigatewayv2_api', 'aws_iam_role_policy_attachment']                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-007
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: Low

tags
| Title      | Description                                                                       |
|:-----------|:----------------------------------------------------------------------------------|
| cloud      | git                                                                               |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2'] |
| service    | ['terraform']                                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-007
Title: AWS IAM policy allows full administrative privileges\
Test Result: **passed**\
Description : This policy identifies IAM policies with full administrative privileges. IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege like granting only the permissions required to perform a task. Determine what users need to do and then craft policies for them that let the users perform only those tasks, instead of allowing full administrative privileges.\

#### Test Details
- eval: data.rule.iam_administrative_privileges
- id : PR-AWS-TRF-IAM-007

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
| resourceTypes | ['aws_api_gateway_rest_api', 'aws_iam_role', 'aws_api_gateway_resource', 'aws_api_gateway_deployment', 'aws_api_gateway_integration', 'aws_api_gateway_integration_response', 'aws_iam_policy', 'aws_iam_role_policy_attachment', 'aws_api_gateway_method_response', 'aws_api_gateway_method']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-api-gateway-integration/main.tf'] |

- masterTestId: PR-AWS-TRF-IAM-007
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: Low

tags
| Title      | Description                                                                       |
|:-----------|:----------------------------------------------------------------------------------|
| cloud      | git                                                                               |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2'] |
| service    | ['terraform']                                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-IAM-007
Title: AWS IAM policy allows full administrative privileges\
Test Result: **passed**\
Description : This policy identifies IAM policies with full administrative privileges. IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege like granting only the permissions required to perform a task. Determine what users need to do and then craft policies for them that let the users perform only those tasks, instead of allowing full administrative privileges.\

#### Test Details
- eval: data.rule.iam_administrative_privileges
- id : PR-AWS-TRF-IAM-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                              |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT34                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                     |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                          |
| resourceTypes | ['aws_sagemaker_endpoint', 'aws_iam_role', 'aws_s3_bucket', 'aws_sagemaker_model', 'aws_sagemaker_endpoint_configuration', 'aws_s3_bucket_object', 'aws_iam_policy', 'random_integer', 'aws_iam_role_policy_attachment'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: PR-AWS-TRF-IAM-007
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego)
- severity: Low

tags
| Title      | Description                                                                       |
|:-----------|:----------------------------------------------------------------------------------|
| cloud      | git                                                                               |
| compliance | ['CIS', 'CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'SOC 2'] |
| service    | ['terraform']                                                                     |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ACM-001
Title: AWS ACM Certificate with wildcard domain name\
Test Result: **failed**\
Description : This policy identifies ACM Certificates which are using wildcard certificates for wildcard domain name instead of single domain name certificates. ACM allows you to use an asterisk (*) in the domain name to create an ACM Certificate containing a wildcard name that can protect several sites in the same domain. For example, a wildcard certificate issued for *.<compliance-software>.io can match both www.<compliance-software>.io and images.<compliance-software>.io. When you use wildcard certificates, if the private key of a certificate is compromised, then all domain and subdomains that use the compromised certificate are potentially impacted. So it is recommended to use single domain name certificates instead of wildcard certificates to reduce the associated risks with a compromised domain or subdomain.\

#### Test Details
- eval: data.rule.acm_wildcard
- id : PR-AWS-TRF-ACM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT5                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['aws_acm_certificate', 'tls_self_signed_cert', 'tls_private_key']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/main.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/tls.tf'] |

- masterTestId: PR-AWS-TRF-ACM-001
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/acm.rego)
- severity: Low

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ACM-002
Title: AWS Certificate Manager (ACM) has certificates with Certificate Transparency Logging disabled\
Test Result: **failed**\
Description : This policy identifies AWS Certificate Manager certificates in which Certificate Transparency Logging is disabled. AWS Certificate Manager (ACM) is the preferred tool to provision, manage, and deploy your server certificates. Certificate Transparency Logging is used to guard against SSL/TLS certificates that are issued by mistake or by a compromised CA, some browsers require that public certificates issued for your domain can also be recorded. This policy generates alerts for certificates which have transparency logging disabled. As a best practice, it is recommended to enable Transparency logging for all certificates.\

#### Test Details
- eval: data.rule.acm_ct_log
- id : PR-AWS-TRF-ACM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT5                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['aws_acm_certificate', 'tls_self_signed_cert', 'tls_private_key']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/main.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/tls.tf'] |

- masterTestId: PR-AWS-TRF-ACM-002
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/acm.rego)
- severity: Medium

tags
| Title      | Description                        |
|:-----------|:-----------------------------------|
| cloud      | git                                |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800'] |
| service    | ['terraform']                      |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-ACM-003
Title: Ensure that the CertificateManager certificates reference only Private ACMPCA certificate authorities\
Test Result: **failed**\
Description : Ensure that the aws certificate manager/ACMPCA Certificate certificate_authority_arn property references (using Fn::GetAtt or Ref) a Private CA, or that the property is not used.\

#### Test Details
- eval: data.rule.acm_certificate_arn
- id : PR-AWS-TRF-ACM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT5                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['aws_acm_certificate', 'tls_self_signed_cert', 'tls_private_key']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/main.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-rest-api-openapi/tls.tf'] |

- masterTestId: PR-AWS-TRF-ACM-003
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/acm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------

