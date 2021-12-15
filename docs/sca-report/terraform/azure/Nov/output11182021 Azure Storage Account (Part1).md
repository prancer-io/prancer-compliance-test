# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AZURE (Nov 2021)

## All Services

#### AKS: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20AKS.md
#### KeyVault: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20KeyVault.md
#### PostgreSQL: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20PostgreSQL.md
#### SQL Servers: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20SQL%20Servers.md
#### Storage Account (Part1): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20Storage%20Account%20(Part1).md
#### Storage Account (Part2): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20Storage%20Account%20(Part2).md
#### VM: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20VM.md

## Terraform Azure Storage Account Services (Part1)

Source Repository: https://github.com/hashicorp/terraform-provider-azurerm

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/

## Compliance run Meta Data
| Title     | Description                        |
|:----------|:-----------------------------------|
| timestamp | 1637184834855                      |
| snapshot  | master-snapshot_gen                |
| container | scenario-azure-terraform-hashicorp |
| test      | master-test.json                   |

## Results

### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT2                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_app_service_plan', 'azurerm_app_service']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_storage_account', 'azurerm_function_app', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_app_service_plan', 'azurerm_application_insights']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT8                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_storage_account', 'azurerm_function_app', 'azurerm_resource_group', 'azurerm_app_service_plan', 'azurerm_application_insights']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT9                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_storage_account', 'azurerm_function_app', 'azurerm_resource_group', 'azurerm_app_service_plan']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT24                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_storage_account', 'azurerm_batch_pool', 'azurerm_resource_group', 'azurerm_batch_account']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT25                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                              |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_batch_pool', 'azurerm_resource_group', 'azurerm_image', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_batch_account', 'azurerm_virtual_network', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT27                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_storage_account', 'azurerm_cdn_profile', 'azurerm_cdn_endpoint', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT31                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_resource_group', 'azurerm_container_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT43                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_eventgrid_event_subscription', 'azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_storage_queue', 'azurerm_storage_blob']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT46                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_subnet_network_security_group_association', 'azurerm_storage_container', 'azuread_group', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_virtual_network_dns_servers', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_role_assignment', 'azuread_user', 'azurerm_active_directory_domain_service', 'azurerm_user_assigned_identity', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_virtual_network', 'azuread_group_member'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT47                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_subnet_network_security_group_association', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_nat_gateway_public_ip_association', 'azurerm_subnet_nat_gateway_association', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_user_assigned_identity', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_nat_gateway', 'azurerm_virtual_network', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/main.tf']                                                                                                                                                                          |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT69                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT70                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group', 'azurerm_media_asset']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT71                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT91                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_storage_account', 'azurerm_redis_cache', 'azurerm_resource_group']                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT97                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_network']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT107                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT108                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_container', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT109                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT110                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_data_lake_gen2_path', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_user_assigned_identity']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT111                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_stream_analytics_job', 'azurerm_resource_group', 'azurerm_stream_analytics_reference_input_blob']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT123                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['azurerm_availability_set', 'azurerm_storage_account', 'azurerm_lb_backend_address_pool', 'azurerm_lb', 'azurerm_network_interface_nat_rule_association', 'azurerm_lb_rule', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_virtual_network', 'azurerm_public_ip']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT127                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_storage_account', 'azurerm_template_deployment', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_virtual_network']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT139                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_availability_set', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_lb_backend_address_pool', 'azurerm_lb', 'azurerm_lb_rule', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_virtual_network', 'azurerm_public_ip']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT145                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_availability_set', 'azurerm_storage_container', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_virtual_network', 'azurerm_public_ip']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT146                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_network_interface', 'azurerm_virtual_network']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - 
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **failed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-STR-003', 'eval': 'data.rule.storage_secure', 'message': 'data.rule.storage_secure_err', 'remediationDescription': "In 'azurerm_storage_account' resource, set 'enable_https_traffic_only = true' or remove property 'enable_https_traffic_only' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#enable_https_traffic_only' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_STR_003.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT154                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_windows_virtual_machine', 'azurerm_role_assignment', 'azurerm_network_interface', 'azurerm_virtual_network']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT155                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_subnet_route_table_association', 'azurerm_firewall_application_rule_collection', 'azurerm_firewall_network_rule_collection', 'azurerm_route_table', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_network_interface_security_group_association', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_firewall', 'random_string', 'azurerm_virtual_network', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT169                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_network']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-003
Title: Storage Accounts https based secure transfer should be enabled\
Test Result: **passed**\
Description : The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPs for custom domain names, this option is not applied when using a custom domain name.\

#### Test Details
- eval: data.rule.storage_secure
- id : PR-AZR-TRF-STR-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT190                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_windows_virtual_machine_scale_set']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT2                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_app_service_plan', 'azurerm_app_service']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_storage_account', 'azurerm_function_app', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_app_service_plan', 'azurerm_application_insights']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT8                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_storage_account', 'azurerm_function_app', 'azurerm_resource_group', 'azurerm_app_service_plan', 'azurerm_application_insights']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT9                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_storage_account', 'azurerm_function_app', 'azurerm_resource_group', 'azurerm_app_service_plan']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT24                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_storage_account', 'azurerm_batch_pool', 'azurerm_resource_group', 'azurerm_batch_account']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT25                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                              |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_batch_pool', 'azurerm_resource_group', 'azurerm_image', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_batch_account', 'azurerm_virtual_network', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT27                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_storage_account', 'azurerm_cdn_profile', 'azurerm_cdn_endpoint', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT31                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_resource_group', 'azurerm_container_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT43                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_eventgrid_event_subscription', 'azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_storage_queue', 'azurerm_storage_blob']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT46                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_subnet_network_security_group_association', 'azurerm_storage_container', 'azuread_group', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_virtual_network_dns_servers', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_role_assignment', 'azuread_user', 'azurerm_active_directory_domain_service', 'azurerm_user_assigned_identity', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_virtual_network', 'azuread_group_member'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT47                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_subnet_network_security_group_association', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_nat_gateway_public_ip_association', 'azurerm_subnet_nat_gateway_association', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_user_assigned_identity', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_nat_gateway', 'azurerm_virtual_network', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/main.tf']                                                                                                                                                                          |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT69                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT70                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group', 'azurerm_media_asset']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT71                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT91                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_storage_account', 'azurerm_redis_cache', 'azurerm_resource_group']                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT97                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_network']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **passed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT107                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT108                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_container', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT109                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT110                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_data_lake_gen2_path', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_user_assigned_identity']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT111                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_stream_analytics_job', 'azurerm_resource_group', 'azurerm_stream_analytics_reference_input_blob']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT123                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['azurerm_availability_set', 'azurerm_storage_account', 'azurerm_lb_backend_address_pool', 'azurerm_lb', 'azurerm_network_interface_nat_rule_association', 'azurerm_lb_rule', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_virtual_network', 'azurerm_public_ip']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT127                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_storage_account', 'azurerm_template_deployment', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_virtual_network']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT139                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_availability_set', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_lb_backend_address_pool', 'azurerm_lb', 'azurerm_lb_rule', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_virtual_network', 'azurerm_public_ip']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT145                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_availability_set', 'azurerm_storage_container', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_virtual_network', 'azurerm_public_ip']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT146                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_network_interface', 'azurerm_virtual_network']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - 
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-STR-004', 'eval': 'data.rule.storage_acl', 'message': 'data.rule.storage_acl_err', 'remediationDescription': "In 'azurerm_storage_account_network_rules' resource or azurerm_storage_account's inner block 'network_rules', set 'default_action = Deny' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#default_action' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_STR_004.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT154                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_windows_virtual_machine', 'azurerm_role_assignment', 'azurerm_network_interface', 'azurerm_virtual_network']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT155                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_subnet_route_table_association', 'azurerm_firewall_application_rule_collection', 'azurerm_firewall_network_rule_collection', 'azurerm_route_table', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_network_interface_security_group_association', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_firewall', 'random_string', 'azurerm_virtual_network', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT169                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_network']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-004
Title: Storage Accounts should have firewall rules enabled\
Test Result: **failed**\
Description : Turning on firewall rules for your storage account blocks incoming requests for data by default, unless the requests come from a service that is operating within an Azure Virtual Network (VNet). Requests that are blocked include those from other Azure services, from the Azure portal, from logging and metrics services, and so on.<br><br>You can grant access to Azure services that operate from within a VNet by allowing the subnet of the service instance. Enable a limited number of scenarios through the Exceptions mechanism described in the following section. To access the Azure portal, you would need to be on a machine within the trusted boundary (either IP or VNet) that you set up.\

#### Test Details
- eval: data.rule.storage_acl
- id : PR-AZR-TRF-STR-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT190                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_windows_virtual_machine_scale_set']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT2                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_app_service_plan', 'azurerm_app_service']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_storage_account', 'azurerm_function_app', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_app_service_plan', 'azurerm_application_insights']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT8                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_storage_account', 'azurerm_function_app', 'azurerm_resource_group', 'azurerm_app_service_plan', 'azurerm_application_insights']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT9                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_storage_account', 'azurerm_function_app', 'azurerm_resource_group', 'azurerm_app_service_plan']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT24                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_storage_account', 'azurerm_batch_pool', 'azurerm_resource_group', 'azurerm_batch_account']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT25                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                              |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_batch_pool', 'azurerm_resource_group', 'azurerm_image', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_batch_account', 'azurerm_virtual_network', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT27                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_storage_account', 'azurerm_cdn_profile', 'azurerm_cdn_endpoint', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT31                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_resource_group', 'azurerm_container_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT43                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_eventgrid_event_subscription', 'azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_storage_queue', 'azurerm_storage_blob']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT46                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_subnet_network_security_group_association', 'azurerm_storage_container', 'azuread_group', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_virtual_network_dns_servers', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_role_assignment', 'azuread_user', 'azurerm_active_directory_domain_service', 'azurerm_user_assigned_identity', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_virtual_network', 'azuread_group_member'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT47                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_subnet_network_security_group_association', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_nat_gateway_public_ip_association', 'azurerm_subnet_nat_gateway_association', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_user_assigned_identity', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_nat_gateway', 'azurerm_virtual_network', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/main.tf']                                                                                                                                                                          |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT69                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT70                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group', 'azurerm_media_asset']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT71                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT91                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_storage_account', 'azurerm_redis_cache', 'azurerm_resource_group']                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT97                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_network']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT107                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT108                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_container', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT109                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT110                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_data_lake_gen2_path', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_user_assigned_identity']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT111                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_stream_analytics_job', 'azurerm_resource_group', 'azurerm_stream_analytics_reference_input_blob']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT123                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['azurerm_availability_set', 'azurerm_storage_account', 'azurerm_lb_backend_address_pool', 'azurerm_lb', 'azurerm_network_interface_nat_rule_association', 'azurerm_lb_rule', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_virtual_network', 'azurerm_public_ip']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT127                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_storage_account', 'azurerm_template_deployment', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_virtual_network']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT139                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_availability_set', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_lb_backend_address_pool', 'azurerm_lb', 'azurerm_lb_rule', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_virtual_network', 'azurerm_public_ip']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT145                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_availability_set', 'azurerm_storage_container', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_virtual_network', 'azurerm_public_ip']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT146                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_network_interface', 'azurerm_virtual_network']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - 
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-STR-005', 'eval': 'data.rule.storage_threat_protection', 'message': 'data.rule.storage_threat_protection_err', 'remediationDescription': "In 'azurerm_advanced_threat_protection' resource, set 'enabled = true' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/advanced_threat_protection#enabled' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_STR_005.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT154                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_windows_virtual_machine', 'azurerm_role_assignment', 'azurerm_network_interface', 'azurerm_virtual_network']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT155                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_subnet_route_table_association', 'azurerm_firewall_application_rule_collection', 'azurerm_firewall_network_rule_collection', 'azurerm_route_table', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_network_interface_security_group_association', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_firewall', 'random_string', 'azurerm_virtual_network', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT169                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_network']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-005
Title: Advanced Threat Protection should be enabled for storage account\
Test Result: **failed**\
Description : Advanced Threat Protection should be enabled for all the storage accounts\

#### Test Details
- eval: data.rule.storage_threat_protection
- id : PR-AZR-TRF-STR-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT190                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_windows_virtual_machine_scale_set']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT2                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_app_service_plan', 'azurerm_app_service']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT7                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_storage_account', 'azurerm_function_app', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_app_service_plan', 'azurerm_application_insights']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT8                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_storage_account', 'azurerm_function_app', 'azurerm_resource_group', 'azurerm_app_service_plan', 'azurerm_application_insights']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT9                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_storage_account', 'azurerm_function_app', 'azurerm_resource_group', 'azurerm_app_service_plan']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT24                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_storage_account', 'azurerm_batch_pool', 'azurerm_resource_group', 'azurerm_batch_account']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT25                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                              |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_batch_pool', 'azurerm_resource_group', 'azurerm_image', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_batch_account', 'azurerm_virtual_network', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT27                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_storage_account', 'azurerm_cdn_profile', 'azurerm_cdn_endpoint', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT31                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_resource_group', 'azurerm_container_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT43                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_eventgrid_event_subscription', 'azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_storage_queue', 'azurerm_storage_blob']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT46                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_subnet_network_security_group_association', 'azurerm_storage_container', 'azuread_group', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_virtual_network_dns_servers', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_role_assignment', 'azuread_user', 'azurerm_active_directory_domain_service', 'azurerm_user_assigned_identity', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_virtual_network', 'azuread_group_member'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT47                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_subnet_network_security_group_association', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_nat_gateway_public_ip_association', 'azurerm_subnet_nat_gateway_association', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_user_assigned_identity', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_nat_gateway', 'azurerm_virtual_network', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/main.tf']                                                                                                                                                                          |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT69                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT70                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group', 'azurerm_media_asset']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT71                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT91                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_storage_account', 'azurerm_redis_cache', 'azurerm_resource_group']                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT97                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_network']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT107                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **failed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT108                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_container', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT109                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT110                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_data_lake_gen2_path', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_user_assigned_identity']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT111                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_stream_analytics_job', 'azurerm_resource_group', 'azurerm_stream_analytics_reference_input_blob']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT123                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['azurerm_availability_set', 'azurerm_storage_account', 'azurerm_lb_backend_address_pool', 'azurerm_lb', 'azurerm_network_interface_nat_rule_association', 'azurerm_lb_rule', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_virtual_network', 'azurerm_public_ip']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT127                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_storage_account', 'azurerm_template_deployment', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_virtual_network']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT139                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_availability_set', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_lb_backend_address_pool', 'azurerm_lb', 'azurerm_lb_rule', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_virtual_network', 'azurerm_public_ip']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT145                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_availability_set', 'azurerm_storage_container', 'azurerm_network_security_group', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_interface', 'azurerm_virtual_network', 'azurerm_public_ip']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT146                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_network_interface', 'azurerm_virtual_network']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - 
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **failed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-STR-010', 'eval': 'data.rule.storage_account_public_access_disabled', 'message': 'data.rule.storage_account_public_access_disabled_err', 'remediationDescription': "In 'azurerm_storage_account' resource, set 'allow_blob_public_access = false' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#allow_blob_public_access' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_STR_010.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-010
Title: Ensure that Storage Account should not allow public access to all blobs or containers\
Test Result: **passed**\
Description : This policy will identify which Storage Account has public access not disabled for all blobs or containers and alert\

#### Test Details
- eval: data.rule.storage_account_public_access_disabled
- id : PR-AZR-TRF-STR-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT154                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_storage_account', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_windows_virtual_machine', 'azurerm_role_assignment', 'azurerm_network_interface', 'azurerm_virtual_network']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------

