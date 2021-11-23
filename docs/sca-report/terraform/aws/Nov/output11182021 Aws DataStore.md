# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AWS (Nov 2021)

## Terraform AWS Data Store Services 

Source Repository: https://github.com/hashicorp/terraform-provider-aws

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/

## Compliance run Meta Data
| Title     | Description         |
|:----------|:--------------------|
| timestamp | 1637184834855       |
| snapshot  | master-snapshot_gen |
| container | scenario-google-KCC |
| test      | master-test.json    |

## Results

### Test ID - PR-AWS-TRF-EFS-001
Title: AWS Elastic File System (EFS) not encrypted using Customer Managed Key\
Test Result: **failed**\
Description : This policy identifies Elastic File Systems (EFSs) which are encrypted with default KMS keys and not with Keys managed by Customer. It is a best practice to use customer managed KMS Keys to encrypt your EFS data. It gives you full control over the encrypted data.\

#### Test Details
- eval: data.rule.efs_kms
- id : PR-AWS-TRF-EFS-001

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
| resourceTypes | ['aws_efs_access_point', 'aws_iam_role_policy_attachment', 'aws_lambda_function', 'aws_efs_mount_target', 'aws_default_subnet', 'aws_default_vpc', 'aws_default_security_group', 'aws_efs_file_system', 'aws_iam_role']                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/main.tf'] |

- masterTestId: TEST_STORAGE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-EFS-002
Title: AWS Elastic File System (EFS) with encryption for data at rest disabled\
Test Result: **failed**\
Description : This policy identifies Elastic File Systems (EFSs) for which encryption for data at rest disabled. It is highly recommended to implement at-rest encryption in order to prevent unauthorized users from reading sensitive data saved to EFS.\

#### Test Details
- eval: data.rule.efs_encrypt
- id : PR-AWS-TRF-EFS-002

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
| resourceTypes | ['aws_efs_access_point', 'aws_iam_role_policy_attachment', 'aws_lambda_function', 'aws_efs_mount_target', 'aws_default_subnet', 'aws_default_vpc', 'aws_default_security_group', 'aws_efs_file_system', 'aws_iam_role']                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/lambda-file-systems/main.tf'] |

- masterTestId: TEST_STORAGE_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets. It is recommended that Access logging is turned on for all S3 buckets to meet audit PR-AWS-TRF-S3-001-DESC compliance requirement\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-TRF-S3-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_s3_bucket', 'aws_s3_bucket_object']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/main.tf'] |

- masterTestId: TEST_STORAGE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['terraform']                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-001
Title: AWS Access logging not enabled on S3 buckets\
Test Result: **failed**\
Description : Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets. It is recommended that Access logging is turned on for all S3 buckets to meet audit PR-AWS-TRF-S3-001-DESC compliance requirement\

#### Test Details
- eval: data.rule.s3_accesslog
- id : PR-AWS-TRF-S3-001

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
| resourceTypes | ['aws_s3_bucket_object', 'aws_iam_role_policy_attachment', 'aws_sagemaker_endpoint_configuration', 'random_integer', 'aws_sagemaker_model', 'aws_s3_bucket', 'aws_iam_policy', 'aws_sagemaker_endpoint', 'aws_iam_role'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: TEST_STORAGE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['CSA-CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI-DSS', 'SOC 2'] |
| service    | ['terraform']                                                  |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **passed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-TRF-S3-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_s3_bucket', 'aws_s3_bucket_object']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/main.tf'] |

- masterTestId: TEST_STORAGE_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-007
Title: AWS S3 Object Versioning is disabled\
Test Result: **passed**\
Description : This policy identifies the S3 buckets which have Object Versioning disabled. S3 Object Versioning is an important capability in protecting your data within a bucket. Once you enable Object Versioning, you cannot remove it; you can suspend Object Versioning at any time on a bucket if you do not wish for it to persist. It is recommended to enable Object Versioning on S3.\

#### Test Details
- eval: data.rule.s3_versioning
- id : PR-AWS-TRF-S3-007

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
| resourceTypes | ['aws_s3_bucket_object', 'aws_iam_role_policy_attachment', 'aws_sagemaker_endpoint_configuration', 'random_integer', 'aws_sagemaker_model', 'aws_s3_bucket', 'aws_iam_policy', 'aws_sagemaker_endpoint', 'aws_iam_role'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: TEST_STORAGE_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-TRF-S3-013

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_s3_bucket', 'aws_s3_bucket_object']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/main.tf'] |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['ISO 27001'] |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-013
Title: S3 buckets with configurations set to host websites\
Test Result: **passed**\
Description : To host a website on AWS S3 you should configure a bucket as a website. This policy identifies all the S3 buckets that are configured to host websites. By frequently surveying these S3 buckets you can ensure that only authorized buckets are enabled to host websites. Make sure to disable static website hosting for unauthorized S3 buckets.\

#### Test Details
- eval: data.rule.s3_website
- id : PR-AWS-TRF-S3-013

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
| resourceTypes | ['aws_s3_bucket_object', 'aws_iam_role_policy_attachment', 'aws_sagemaker_endpoint_configuration', 'random_integer', 'aws_sagemaker_model', 'aws_s3_bucket', 'aws_iam_policy', 'aws_sagemaker_endpoint', 'aws_iam_role'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: TEST_STORAGE_11
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['ISO 27001'] |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-TRF-S3-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_s3_bucket', 'aws_s3_bucket_object']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/main.tf'] |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-008
Title: AWS S3 bucket has global view ACL permissions enabled.\
Test Result: **passed**\
Description : This policy determines if any S3 bucket(s) has Global View ACL permissions enabled for the All Users group. These permissions allow external resources to see the permission settings associated to the object.\

#### Test Details
- eval: data.rule.s3_public_acl
- id : PR-AWS-TRF-S3-008

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
| resourceTypes | ['aws_s3_bucket_object', 'aws_iam_role_policy_attachment', 'aws_sagemaker_endpoint_configuration', 'random_integer', 'aws_sagemaker_model', 'aws_s3_bucket', 'aws_iam_policy', 'aws_sagemaker_endpoint', 'aws_iam_role'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: TEST_STORAGE_13
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-TRF-S3-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_s3_bucket', 'aws_s3_bucket_object']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/main.tf'] |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: high

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-010
Title: AWS S3 buckets are accessible to any authenticated user.\
Test Result: **passed**\
Description : This policy identifies S3 buckets accessible to any authenticated AWS users. Amazon S3 allows customer to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example to host website content. However, these buckets often contain highly sensitive enterprise data which if left accessible to anyone with valid AWS credentials, may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_auth_acl
- id : PR-AWS-TRF-S3-010

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
| resourceTypes | ['aws_s3_bucket_object', 'aws_iam_role_policy_attachment', 'aws_sagemaker_endpoint_configuration', 'random_integer', 'aws_sagemaker_model', 'aws_s3_bucket', 'aws_iam_policy', 'aws_sagemaker_endpoint', 'aws_iam_role'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: TEST_STORAGE_14
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: high

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-TRF-S3-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_s3_bucket', 'aws_s3_bucket_object']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/main.tf'] |

- masterTestId: TEST_STORAGE_15
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: high

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-011
Title: AWS S3 buckets are accessible to public\
Test Result: **passed**\
Description : This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store and retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.\

#### Test Details
- eval: data.rule.s3_public_access
- id : PR-AWS-TRF-S3-011

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
| resourceTypes | ['aws_s3_bucket_object', 'aws_iam_role_policy_attachment', 'aws_sagemaker_endpoint_configuration', 'random_integer', 'aws_sagemaker_model', 'aws_s3_bucket', 'aws_iam_policy', 'aws_sagemaker_endpoint', 'aws_iam_role'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: TEST_STORAGE_15
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: high

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-TRF-S3-012

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_s3_bucket', 'aws_s3_bucket_object']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/main.tf'] |

- masterTestId: TEST_STORAGE_16
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-012
Title: AWS S3 buckets do not have server side encryption.\
Test Result: **failed**\
Description : Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.\

#### Test Details
- eval: data.rule.s3_encryption
- id : PR-AWS-TRF-S3-012

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
| resourceTypes | ['aws_s3_bucket_object', 'aws_iam_role_policy_attachment', 'aws_sagemaker_endpoint_configuration', 'random_integer', 'aws_sagemaker_model', 'aws_s3_bucket', 'aws_iam_policy', 'aws_sagemaker_endpoint', 'aws_iam_role'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: TEST_STORAGE_16
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-TRF-S3-014

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_s3_bucket', 'aws_s3_bucket_object']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/main.tf'] |

- masterTestId: TEST_STORAGE_17
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-014
Title: Ensure S3 hosted sites supported hardened CORS\
Test Result: **passed**\
Description : Ensure that AllowedOrigins, AllowedMethods should not be set to *. this allows all cross site users to access s3 bucket and they have permission to manipulate data\

#### Test Details
- eval: data.rule.s3_cors
- id : PR-AWS-TRF-S3-014

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
| resourceTypes | ['aws_s3_bucket_object', 'aws_iam_role_policy_attachment', 'aws_sagemaker_endpoint_configuration', 'random_integer', 'aws_sagemaker_model', 'aws_s3_bucket', 'aws_iam_policy', 'aws_sagemaker_endpoint', 'aws_iam_role'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: TEST_STORAGE_17
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-TRF-S3-015

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_s3_bucket', 'aws_s3_bucket_object']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/main.tf'] |

- masterTestId: TEST_STORAGE_19
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-015
Title: Ensure S3 bucket is encrypted using KMS\
Test Result: **failed**\
Description : Ensure that your AWS S3 buckets are configured to use Server-Side Encryption with customer managed CMKs instead of S3-Managed Keys (SSE-S3) in order to obtain a fine-grained control over Amazon S3 data-at-rest encryption and decryption process\

#### Test Details
- eval: data.rule.bucket_kms_encryption
- id : PR-AWS-TRF-S3-015

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
| resourceTypes | ['aws_s3_bucket_object', 'aws_iam_role_policy_attachment', 'aws_sagemaker_endpoint_configuration', 'random_integer', 'aws_sagemaker_model', 'aws_s3_bucket', 'aws_iam_policy', 'aws_sagemaker_endpoint', 'aws_iam_role'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: TEST_STORAGE_19
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable object_lock_enabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-TRF-S3-016

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_s3_bucket', 'aws_s3_bucket_object']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/main.tf'] |

- masterTestId: TEST_STORAGE_20
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-016
Title: Ensure S3 bucket has enabled lock configuration\
Test Result: **failed**\
Description : Indicates whether this bucket has an Object Lock configuration enabled. Enable object_lock_enabled when you apply ObjectLockConfiguration to a bucket.\

#### Test Details
- eval: data.rule.s3_object_lock_enable
- id : PR-AWS-TRF-S3-016

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
| resourceTypes | ['aws_s3_bucket_object', 'aws_iam_role_policy_attachment', 'aws_sagemaker_endpoint_configuration', 'random_integer', 'aws_sagemaker_model', 'aws_s3_bucket', 'aws_iam_policy', 'aws_sagemaker_endpoint', 'aws_iam_role'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: TEST_STORAGE_20
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-TRF-S3-017

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['aws_s3_bucket', 'aws_s3_bucket_object']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/s3-cross-account-access/main.tf'] |

- masterTestId: TEST_STORAGE_21
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-S3-017
Title: Ensure S3 bucket cross-region replication is enabled\
Test Result: **failed**\
Description : Cross-region replication enables automatic, asynchronous copying of objects across S3 buckets. By default, replication supports copying new S3 objects after it is enabled\

#### Test Details
- eval: data.rule.s3_cross_region_replica
- id : PR-AWS-TRF-S3-017

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
| resourceTypes | ['aws_s3_bucket_object', 'aws_iam_role_policy_attachment', 'aws_sagemaker_endpoint_configuration', 'random_integer', 'aws_sagemaker_model', 'aws_s3_bucket', 'aws_iam_policy', 'aws_sagemaker_endpoint', 'aws_iam_role'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/sagemaker/main.tf']                                                                                                                             |

- masterTestId: TEST_STORAGE_21
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-DD-001
Title: AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK\
Test Result: **passed**\
Description : This policy identifies the DynamoDB tables that use AWS owned CMK (default ) instead of AWS managed CMK (KMS ) to encrypt data. AWS managed CMK provide additional features such as the ability to view the CMK and key policy, and audit the encryption and decryption of DynamoDB tables.\

#### Test Details
- eval: data.rule.dynamodb_encrypt
- id : PR-AWS-TRF-DD-001

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
| resourceTypes | ['aws_iam_role_policy_attachment', 'aws_lambda_function', 'aws_dynamodb_table', 'aws_apigatewayv2_integration', 'aws_apigatewayv2_api', 'aws_apigatewayv2_stage', 'aws_lambda_permission', 'aws_iam_policy', 'aws_apigatewayv2_route', 'aws_apigatewayv2_deployment', 'aws_iam_role']                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/api-gateway-websocket-chat-app/main.tf'] |

- masterTestId: TEST_DATABASE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-RDS-002
Title: AWS RDS database instance is publicly accessible\
Test Result: **passed**\
Description : This policy identifies RDS database instances which are publicly accessible.DB instances should not be publicly accessible to protect the integrety of data.Public accessibility of DB instances can be modified by turning on or off the Public accessibility parameter.\

#### Test Details
- eval: data.rule.rds_public
- id : PR-AWS-TRF-RDS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_db_instance', 'aws_db_subnet_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/main.tf'] |

- masterTestId: TEST_DATABASE_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego)
- severity: Medium

tags
| Title      | Description                                     |
|:-----------|:------------------------------------------------|
| cloud      | git                                             |
| compliance | ['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800'] |
| service    | ['terraform']                                   |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-RDS-006
Title: AWS RDS instance is not encrypted\
Test Result: **failed**\
Description : This policy identifies AWS RDS instances which are not encrypted. Amazon Relational Database Service (Amazon RDS) is a web service that makes it easier to set up and manage databases. Amazon allows customers to turn on encryption for RDS which is recommended for compliance and security reasons.\

#### Test Details
- eval: data.rule.rds_encrypt
- id : PR-AWS-TRF-RDS-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_db_instance', 'aws_db_subnet_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/main.tf'] |

- masterTestId: TEST_DATABASE_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego)
- severity: Medium

tags
| Title      | Description                                                                             |
|:-----------|:----------------------------------------------------------------------------------------|
| cloud      | git                                                                                     |
| compliance | ['CSA-CCM', 'GDPR', 'HIPAA', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                                           |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-RDS-007
Title: AWS RDS instance with Multi-Availability Zone disabled\
Test Result: **failed**\
Description : This policy identifies RDS instances which have Multi-Availability Zone(Multi-AZ) disabled. When RDS DB instance is enabled with Multi-AZ, RDS automatically creates a primary DB Instance and synchronously replicates the data to a standby instance in a different availability zone. These Multi-AZ deployments will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primaryâ€™s availability zone for read/write operations, so by making them the best fit for production database workloads.\

#### Test Details
- eval: data.rule.rds_multiaz
- id : PR-AWS-TRF-RDS-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_db_instance', 'aws_db_subnet_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/main.tf'] |

- masterTestId: TEST_DATABASE_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-RDS-008
Title: AWS RDS instance with copy tags to snapshots disabled\
Test Result: **failed**\
Description : This policy identifies RDS instances which have copy tags to snapshots disabled. Copy tags to snapshots copies all the user-defined tags from the DB instance to snapshots. Copying tags allow you to add metadata and apply access policies to your Amazon RDS resources.\

#### Test Details
- eval: data.rule.rds_snapshot
- id : PR-AWS-TRF-RDS-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_db_instance', 'aws_db_subnet_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/main.tf'] |

- masterTestId: TEST_DATABASE_10
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-RDS-009
Title: AWS RDS instance without Automatic Backup setting\
Test Result: **failed**\
Description : This policy identifies RDS instances which are not set with the Automatic Backup setting. If Automatic Backup is set, RDS creates a storage volume snapshot of your DB instance, backing up the entire DB instance and not just individual databases which provide for point-in-time recovery. The automatic backup will happen during the specified backup window time and keeps the backups for a limited period of time as defined in the retention period. It is recommended to set Automatic backups for your critical RDS servers that will help in the data restoration process.\

#### Test Details
- eval: data.rule.rds_backup
- id : PR-AWS-TRF-RDS-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_db_instance', 'aws_db_subnet_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/main.tf'] |

- masterTestId: TEST_DATABASE_11
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-RDS-010
Title: AWS RDS minor upgrades not enabled\
Test Result: **failed**\
Description : When Amazon Relational Database Service (Amazon RDS) supports a new version of a database engine, you can upgrade your DB instances to the new version. There are two kinds of upgrades: major version upgrades and minor version upgrades. Minor upgrades helps maintain a secure and stable RDS with minimal impact on the application. For this reason, we recommend that your automatic minor upgrade is enabled. Minor version upgrades only occur automatically if a minor upgrade replaces an unsafe version, such as a minor upgrade that contains bug fixes for a previous version.\

#### Test Details
- eval: data.rule.rds_upgrade
- id : PR-AWS-TRF-RDS-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_db_instance', 'aws_db_subnet_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/main.tf'] |

- masterTestId: TEST_DATABASE_12
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-RDS-011
Title: AWS RDS retention policy less than 7 days\
Test Result: **failed**\
Description : RDS Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).\

#### Test Details
- eval: data.rule.rds_retention
- id : PR-AWS-TRF-RDS-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_db_instance', 'aws_db_subnet_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/main.tf'] |

- masterTestId: TEST_DATABASE_13
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AWS-TRF-RDS-003
Title: AWS RDS database not encrypted using Customer Managed Key\
Test Result: **failed**\
Description : This policy identifies RDS databases that are encrypted with default KMS keys and not with customer managed keys. As a best practice, use customer managed keys to encrypt the data on your RDS databases and maintain control of your keys and data on sensitive workloads.\

#### Test Details
- eval: data.rule.rds_encrypt_key
- id : PR-AWS-TRF-RDS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAwsTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['aws_db_instance', 'aws_db_subnet_group']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/outputs.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/sg-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/subnet-variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/terraform.template.tfvars', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/variables.tf', 'https://github.com/hashicorp/terraform-provider-aws/tree/main/examples/rds/main.tf'] |

- masterTestId: TEST_DATABASE_14
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------

